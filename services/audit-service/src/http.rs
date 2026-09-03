//! HTTP query surface for the audit log.
//!
//! The audit log has been queryable over gRPC since the service existed, and
//! only over gRPC — this module's absence is why the dashboard's activity feed
//! and the whole `/audit` page answered 404 against `/v1/audit/events`. Browsers
//! do not speak gRPC, so the one consumer that most needs to read the log had
//! no way to.
//!
//! ## Tenant scoping
//!
//! [`AuditStoreBackend::query_events`] takes a `tenant_id: &str`, not an
//! `Option`, so a caller cannot accidentally widen the query to every tenant —
//! the type makes the unscoped read unrepresentable here. The tenant comes from
//! [`wslvault_core::auth::resolve_identity`] and never from a query parameter:
//! the audit log records who did what, and letting a caller name the tenant
//! they want to read would make it a cross-tenant disclosure channel.
//!
//! A superuser reads another tenant's log by acting as that tenant
//! (`ACT_AS_TENANT_HEADER`), which `resolve_identity` already resolves — so
//! that path stays a signed claim rather than a parameter.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::store::{AuditRecord, AuditStoreBackend};

/// Page size when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 100;

/// Ceiling on page size. A caller asking for more gets this instead of an
/// error: the log is append-only and unbounded, and an unclamped `limit` turns
/// one request into an unbounded database read.
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    /// Exact match on the structured action, e.g. `secret.read`.
    action: Option<String>,
    /// Exact match on the acting principal.
    principal: Option<String>,
    /// Inclusive lower bound on `timestamp`, RFC 3339.
    from: Option<String>,
    /// Inclusive upper bound on `timestamp`, RFC 3339.
    to: Option<String>,
}

/// One event as the UI consumes it.
///
/// Deliberately not `AuditRecord` verbatim. `signature`, `seq` and `prev_hash`
/// are the tamper-evidence chain: they are verified server-side on read, and
/// publishing them to every reader invites a client to "verify" the chain with
/// the same data it would need to forge one convincingly.
#[derive(Debug, Serialize)]
pub struct AuditEventView {
    event_id: String,
    action: String,
    resource: String,
    principal: String,
    outcome: String,
    timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    /// Whether this record's signature verified when it was read back.
    ///
    /// Included deliberately, where the signature itself is not. This is the
    /// *result* of the tamper-evidence check and leaks none of the material
    /// needed to forge one — and an audit log that renders an altered record
    /// indistinguishably from a sound one is worse than no audit log, because
    /// it is trusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
}

impl From<AuditRecord> for AuditEventView {
    fn from(r: AuditRecord) -> Self {
        // The store returns "" rather than NULL for these (the columns are
        // COALESCEd in SQL), so map empty back to absent instead of rendering
        // an empty row in the table.
        let non_empty = |s: String| if s.is_empty() { None } else { Some(s) };

        Self {
            event_id: r.id.to_string(),
            action: r.action,
            resource: r.resource,
            principal: r.principal_id,
            outcome: r.outcome,
            timestamp: r.timestamp,
            outcome_detail: non_empty(r.outcome_detail),
            ip_address: non_empty(r.client_ip),
            metadata: match r.details {
                serde_json::Value::Null => None,
                v => Some(v),
            },
            verified: r.verified,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    events: Vec<AuditEventView>,
    /// Matching rows before `limit`/`offset`, for pagination.
    total: usize,
}

/// Parse an RFC 3339 bound, naming which parameter was wrong.
///
/// An unparseable bound is rejected rather than ignored: silently dropping it
/// would widen the query and hand the caller more of the log than they asked
/// for, while looking like it worked.
fn parse_bound(raw: Option<&String>, field: &str) -> Result<Option<DateTime<Utc>>, Response> {
    match raw {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(dt) => Ok(Some(dt.with_timezone(&Utc))),
            Err(e) => Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "message": format!("`{field}` must be an RFC 3339 timestamp: {e}")
                })),
            )
                .into_response()),
        },
    }
}

/// `GET /v1/audit/events`
async fn list_events(
    State(store): State<Arc<dyn AuditStoreBackend>>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    let identity = match wslvault_core::auth::resolve_identity(&headers).await {
        Ok(i) => i,
        Err(reason) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "message": reason.0 })),
            )
                .into_response()
        }
    };

    let start_time = match parse_bound(q.from.as_ref(), "from") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let end_time = match parse_bound(q.to.as_ref(), "to") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `limit == 0` means "all" to the backend, which is not something an HTTP
    // caller should be able to ask for.
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let empty_to_none = |s: &Option<String>| -> Option<String> {
        s.as_ref().filter(|v| !v.trim().is_empty()).cloned()
    };
    let action = empty_to_none(&q.action);
    let principal = empty_to_none(&q.principal);

    match store
        .query_events(
            &identity.tenant_id,
            start_time,
            end_time,
            action.as_deref(),
            principal.as_deref(),
            limit,
            q.offset.unwrap_or(0),
        )
        .await
    {
        Ok((records, total)) => Json(EventsResponse {
            events: records.into_iter().map(AuditEventView::from).collect(),
            total,
        })
        .into_response(),
        Err(e) => {
            // The detail goes to the log, not the caller: query errors can echo
            // filter values back, and this endpoint is reachable by any
            // authenticated principal.
            error!(error = %e, tenant_id = %identity.tenant_id, "audit query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "audit query failed" })),
            )
                .into_response()
        }
    }
}

/// Routes served alongside `/health` on the HTTP port.
pub fn router(store: Arc<dyn AuditStoreBackend>) -> Router {
    Router::new()
        .route("/v1/audit/events", get(list_events))
        .with_state(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_bad_timestamp_rather_than_ignoring_it() {
        let bad = Some("not-a-date".to_string());
        assert!(parse_bound(bad.as_ref(), "from").is_err());
    }

    #[test]
    fn treats_blank_as_absent() {
        // The UI sends `from=` when its filter box is empty.
        let blank = Some("   ".to_string());
        assert_eq!(parse_bound(blank.as_ref(), "from").unwrap(), None);
        assert_eq!(parse_bound(None, "from").unwrap(), None);
    }

    #[test]
    fn accepts_rfc3339() {
        let ok = Some("2026-09-02T10:00:00Z".to_string());
        assert!(parse_bound(ok.as_ref(), "to").unwrap().is_some());
    }

    /// The chain fields are tamper-evidence, not payload.
    #[test]
    fn view_omits_the_signature_chain() {
        let rec = AuditRecord {
            id: uuid::Uuid::nil(),
            tenant_id: "t".into(),
            principal_id: "p".into(),
            action: "secret.read".into(),
            resource: "secret/x".into(),
            outcome: "success".into(),
            outcome_detail: String::new(),
            details: serde_json::Value::Null,
            client_ip: String::new(),
            signature: "SIGNATURE-SHOULD-NOT-LEAK".into(),
            timestamp: Utc::now(),
            seq: 7,
            prev_hash: "PREV-HASH-SHOULD-NOT-LEAK".into(),
            verified: Some(true),
        };
        let json = serde_json::to_string(&AuditEventView::from(rec)).unwrap();
        assert!(!json.contains("SIGNATURE-SHOULD-NOT-LEAK"));
        assert!(!json.contains("PREV-HASH-SHOULD-NOT-LEAK"));
        // Empty strings become absent rather than empty table cells.
        assert!(!json.contains("ip_address"));
    }
}
