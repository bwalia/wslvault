//! gRPC service implementation for the WSLVault PolicyService.
//!
//! Translates incoming proto messages into domain operations, delegates to
//! `PolicyStore` for persistence and `CompiledPolicies` for evaluation, then
//! converts results back to proto types. All domain errors are mapped to
//! appropriate `tonic::Status` codes.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::{debug, instrument, warn};

use crate::evaluator::{self, CompiledPolicies};
use crate::model::{Capability, PolicyDecision, PolicyDocument, PolicyRule};
use crate::proto::policy_service_server::PolicyService;
use crate::proto::{
    AuthorizeRequest, AuthorizeResponse, DeletePolicyRequest, DeletePolicyResponse,
    GetPolicyRequest, GetPolicyResponse, ListPoliciesRequest, ListPoliciesResponse,
    PolicyDocument as ProtoPolicyDocument, PolicyRule as ProtoPolicyRule, PutPolicyRequest,
    PutPolicyResponse,
};
use crate::store::PolicyStore;

/// The concrete gRPC handler struct. Holds shared references to the mutable
/// policy store and the most-recently-compiled evaluation snapshot.
#[derive(Debug, Clone)]
pub struct PolicyServiceImpl {
    store: PolicyStore,
    compiled: Arc<RwLock<CompiledPolicies>>,
}

impl PolicyServiceImpl {
    /// Create a new service handler.
    ///
    /// * `store` – the mutable policy store; also held by the background
    ///   compilation task.
    /// * `compiled` – the latest compiled snapshot, updated by the background
    ///   task. The gRPC handler reads from this under a read lock
    ///   to avoid blocking writers.
    pub fn new(store: PolicyStore, compiled: Arc<RwLock<CompiledPolicies>>) -> Self {
        Self { store, compiled }
    }
}

// ---------------------------------------------------------------------------
// Proto ↔ domain conversion helpers
// ---------------------------------------------------------------------------

/// Convert a proto `PolicyDocument` into the internal domain representation.
///
/// Returns an error `Status` if a capabilities string is unrecognisable,
/// allowing the caller to surface a clear `INVALID_ARGUMENT` to the client.
#[allow(clippy::result_large_err)]
fn proto_to_domain_document(proto: ProtoPolicyDocument) -> Result<PolicyDocument, Status> {
    let mut rules = Vec::with_capacity(proto.rules.len());

    for proto_rule in proto.rules {
        let capabilities = parse_capabilities(&proto_rule.capabilities)?;
        rules.push(PolicyRule {
            paths: proto_rule.paths,
            capabilities,
        });
    }

    Ok(PolicyDocument {
        name: proto.name,
        rules,
    })
}

/// Parse a list of capability strings into a `HashSet<Capability>`.
///
/// Accepted strings (case-insensitive): read, write, delete, list, create,
/// update, deny. Returns `INVALID_ARGUMENT` for unknown strings.
#[allow(clippy::result_large_err)]
fn parse_capabilities(raw: &[String]) -> Result<HashSet<Capability>, Status> {
    raw.iter()
        .map(|s| match s.to_lowercase().as_str() {
            "read" => Ok(Capability::Read),
            "write" => Ok(Capability::Write),
            "delete" => Ok(Capability::Delete),
            "list" => Ok(Capability::List),
            "create" => Ok(Capability::Create),
            "update" => Ok(Capability::Update),
            "deny" => Ok(Capability::Deny),
            other => Err(Status::invalid_argument(format!(
                "unknown capability: '{other}'"
            ))),
        })
        .collect()
}

/// Convert an internal `PolicyDocument` into its proto equivalent.
fn domain_to_proto_document(doc: PolicyDocument) -> ProtoPolicyDocument {
    let rules = doc
        .rules
        .into_iter()
        .map(|rule| {
            let capabilities = rule
                .capabilities
                .iter()
                .map(|cap| {
                    match cap {
                        Capability::Read => "read",
                        Capability::Write => "write",
                        Capability::Delete => "delete",
                        Capability::List => "list",
                        Capability::Create => "create",
                        Capability::Update => "update",
                        Capability::Deny => "deny",
                    }
                    .to_string()
                })
                .collect();
            ProtoPolicyRule {
                paths: rule.paths,
                capabilities,
            }
        })
        .collect();

    ProtoPolicyDocument {
        name: doc.name,
        rules,
    }
}

// ---------------------------------------------------------------------------
// Tonic trait implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    /// Evaluate an authorization request against the caller's named policies.
    ///
    /// The compiled snapshot is read under a shared (read) lock so concurrent
    /// authorize calls do not block each other or the background recompilation.
    #[instrument(skip(self, request), fields(
        tenant_id  = %request.get_ref().tenant_id,
        principal  = %request.get_ref().principal_id,
        action     = %request.get_ref().action,
        resource   = %request.get_ref().resource,
    ))]
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }
        if req.action.is_empty() {
            return Err(Status::invalid_argument("action must not be empty"));
        }
        if req.resource.is_empty() {
            return Err(Status::invalid_argument("resource must not be empty"));
        }

        let compiled_guard = self.compiled.read().await;
        let decision =
            evaluator::evaluate(&compiled_guard, &req.policies, &req.action, &req.resource);

        debug!(
            tenant_id = %req.tenant_id,
            principal = %req.principal_id,
            action    = %req.action,
            resource  = %req.resource,
            ?decision,
            "authorization decision"
        );

        match decision {
            PolicyDecision::Allow => Ok(Response::new(AuthorizeResponse {
                allowed: true,
                matched_policy: String::new(),
                reason: String::new(),
            })),
            PolicyDecision::Deny { reason } => Ok(Response::new(AuthorizeResponse {
                allowed: false,
                matched_policy: String::new(),
                reason,
            })),
        }
    }

    /// Store (create or replace) a policy document for a tenant.
    #[instrument(skip(self, request), fields(
        tenant_id = %request.get_ref().tenant_id,
    ))]
    async fn put_policy(
        &self,
        request: Request<PutPolicyRequest>,
    ) -> Result<Response<PutPolicyResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        let proto_doc = req
            .policy
            .ok_or_else(|| Status::invalid_argument("policy document must be provided"))?;

        if proto_doc.name.is_empty() {
            return Err(Status::invalid_argument("policy name must not be empty"));
        }

        let policy_id = proto_doc.name.clone();
        let domain_doc = proto_to_domain_document(proto_doc)?;

        self.store.put_policy(&req.tenant_id, domain_doc).await;

        Ok(Response::new(PutPolicyResponse { policy_id }))
    }

    /// Delete a policy by tenant and name.
    #[instrument(skip(self, request), fields(
        tenant_id = %request.get_ref().tenant_id,
        name      = %request.get_ref().name,
    ))]
    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }
        if req.name.is_empty() {
            return Err(Status::invalid_argument("policy name must not be empty"));
        }

        let removed = self.store.delete_policy(&req.tenant_id, &req.name).await;

        if removed.is_none() {
            warn!(
                tenant_id = %req.tenant_id,
                name       = %req.name,
                "attempted to delete non-existent policy"
            );
            return Err(Status::not_found(format!(
                "policy '{}' not found for tenant '{}'",
                req.name, req.tenant_id
            )));
        }

        Ok(Response::new(DeletePolicyResponse {}))
    }

    /// List the names of all policies belonging to a tenant.
    #[instrument(skip(self, request), fields(tenant_id = %request.get_ref().tenant_id))]
    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }

        let names = self.store.list_policies(&req.tenant_id).await;
        Ok(Response::new(ListPoliciesResponse { names }))
    }

    /// Fetch a single policy document by tenant and name.
    #[instrument(skip(self, request), fields(
        tenant_id = %request.get_ref().tenant_id,
        name      = %request.get_ref().name,
    ))]
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let req = request.into_inner();

        if req.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id must not be empty"));
        }
        if req.name.is_empty() {
            return Err(Status::invalid_argument("policy name must not be empty"));
        }

        let doc = self
            .store
            .get_policy(&req.tenant_id, &req.name)
            .await
            .ok_or_else(|| {
                Status::not_found(format!(
                    "policy '{}' not found for tenant '{}'",
                    req.name, req.tenant_id
                ))
            })?;

        Ok(Response::new(GetPolicyResponse {
            policy: Some(domain_to_proto_document(doc)),
        }))
    }
}
