//! SCIM 2.0 server module for the identity-service.
//!
//! Implements the SCIM 2.0 protocol as defined by RFC 7643 (schema) and
//! RFC 7644 (protocol), providing standardised user and group provisioning
//! endpoints for enterprise IdP integration (Okta, Azure AD, etc.).
//!
//! # Endpoint overview
//!
//! | Method   | Path                            | Description                   |
//! |----------|---------------------------------|-------------------------------|
//! | GET      | /scim/v2/ServiceProviderConfig  | Service provider capabilities |
//! | GET      | /scim/v2/Schemas                | All supported schemas         |
//! | GET      | /scim/v2/ResourceTypes          | Supported resource types      |
//! | POST     | /scim/v2/Users                  | Provision a new user          |
//! | GET      | /scim/v2/Users                  | List / filter users           |
//! | GET      | /scim/v2/Users/:id              | Get user by ID                |
//! | PUT      | /scim/v2/Users/:id              | Full user replace             |
//! | PATCH    | /scim/v2/Users/:id              | Partial user update           |
//! | DELETE   | /scim/v2/Users/:id              | Deprovision user              |
//! | POST     | /scim/v2/Groups                 | Provision a new group         |
//! | GET      | /scim/v2/Groups                 | List / filter groups          |
//! | GET      | /scim/v2/Groups/:id             | Get group by ID               |
//! | PUT      | /scim/v2/Groups/:id             | Full group replace            |
//! | PATCH    | /scim/v2/Groups/:id             | Partial group update          |
//! | DELETE   | /scim/v2/Groups/:id             | Deprovision group             |
//!
//! # State
//!
//! All handlers share a [`ScimState`] value that is injected via axum's
//! [`State`] extractor.  The state holds two in-memory stores (users and
//! groups) plus a reference to the identity-service's [`PrincipalStore`] so
//! that SCIM provisioning events can be reflected in wslvault policy
//! enforcement.
//!
//! # Mounting
//!
//! Use [`router`] to obtain a fully-configured `axum::Router<ScimState>` and
//! merge it into the main HTTP app after calling `.with_state(scim_state)`:
//!
//! ```no_run
//! let scim_state = ScimState::new(principal_store.clone());
//! let app = existing_router.merge(scim::router().with_state(scim_state));
//! ```

pub mod groups;
pub mod schemas;
pub mod scim_store;
pub mod users;

use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;

use crate::store::PrincipalStore;

use self::schemas::{
    ScimGroup, ScimUser, SCHEMA_GROUP, SCHEMA_LIST_RESPONSE, SCHEMA_USER,
};
use self::scim_store::{MemoryScimStore, ScimStore};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared mutable state for all SCIM handlers.
///
/// Cloned cheaply (all fields are `Arc`-backed) and inserted as axum
/// application state via `.with_state(scim_state)`.
#[derive(Clone)]
pub struct ScimState {
    /// Pluggable SCIM store: in-memory for tests, PostgreSQL in production.
    pub store: Arc<dyn ScimStore>,

    /// Reference to the identity-service principal store so that SCIM
    /// provisioning events can create and modify wslvault principals.
    pub principals: PrincipalStore,
}

impl ScimState {
    /// Creates an empty `ScimState` with an in-memory store, backed by the
    /// supplied `PrincipalStore`.  Used for tests and when `DATABASE_URL` is
    /// not set.
    pub fn new(principals: PrincipalStore) -> Self {
        Self {
            store: Arc::new(MemoryScimStore::new()),
            principals,
        }
    }

    /// Creates a `ScimState` backed by a PostgreSQL [`ScimStore`]
    /// implementation.
    pub fn with_store(store: Arc<dyn ScimStore>, principals: PrincipalStore) -> Self {
        Self { store, principals }
    }
}

// ---------------------------------------------------------------------------
// Discovery endpoint handlers
// ---------------------------------------------------------------------------

/// `GET /scim/v2/ServiceProviderConfig` — describes server capabilities.
///
/// Returns the set of optional SCIM features supported by this implementation
/// per RFC 7644 §4.
async fn service_provider_config() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://github.com/wslvault/wslvault",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": {
                "supported": true,
                // Limit to prevent unbounded scans.
                "maxResults": 200
            },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using the OAuth Bearer Token Standard",
                    "specUri": "https://www.rfc-editor.org/info/rfc6750",
                    "primary": true
                }
            ],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": "/scim/v2/ServiceProviderConfig"
            }
        })),
    )
}

/// `GET /scim/v2/Schemas` — returns all supported SCIM schemas.
///
/// Enumerates User and Group core schemas per RFC 7643 §7.
async fn list_schemas() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": 2,
            "startIndex": 1,
            "itemsPerPage": 2,
            "Resources": [
                {
                    "id": SCHEMA_USER,
                    "name": "User",
                    "description": "User Account",
                    "attributes": [
                        {
                            "name": "userName",
                            "type": "string",
                            "multiValued": false,
                            "required": true,
                            "caseExact": false,
                            "mutability": "readWrite",
                            "returned": "default",
                            "uniqueness": "server"
                        },
                        {
                            "name": "displayName",
                            "type": "string",
                            "multiValued": false,
                            "required": false,
                            "mutability": "readWrite",
                            "returned": "default"
                        },
                        {
                            "name": "active",
                            "type": "boolean",
                            "multiValued": false,
                            "required": false,
                            "mutability": "readWrite",
                            "returned": "default"
                        },
                        {
                            "name": "emails",
                            "type": "complex",
                            "multiValued": true,
                            "required": false,
                            "mutability": "readWrite",
                            "returned": "default",
                            "subAttributes": [
                                { "name": "value", "type": "string" },
                                { "name": "type", "type": "string" },
                                { "name": "primary", "type": "boolean" }
                            ]
                        },
                        {
                            "name": "name",
                            "type": "complex",
                            "multiValued": false,
                            "required": false,
                            "mutability": "readWrite",
                            "returned": "default",
                            "subAttributes": [
                                { "name": "givenName", "type": "string" },
                                { "name": "familyName", "type": "string" },
                                { "name": "formatted", "type": "string" }
                            ]
                        }
                    ],
                    "meta": {
                        "resourceType": "Schema",
                        "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
                    }
                },
                {
                    "id": SCHEMA_GROUP,
                    "name": "Group",
                    "description": "Group",
                    "attributes": [
                        {
                            "name": "displayName",
                            "type": "string",
                            "multiValued": false,
                            "required": true,
                            "caseExact": false,
                            "mutability": "readWrite",
                            "returned": "default",
                            "uniqueness": "server"
                        },
                        {
                            "name": "members",
                            "type": "complex",
                            "multiValued": true,
                            "required": false,
                            "mutability": "readWrite",
                            "returned": "default",
                            "subAttributes": [
                                { "name": "value", "type": "string" },
                                { "name": "display", "type": "string" },
                                { "name": "type", "type": "string" }
                            ]
                        }
                    ],
                    "meta": {
                        "resourceType": "Schema",
                        "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
                    }
                }
            ]
        })),
    )
}

/// `GET /scim/v2/ResourceTypes` — returns the supported resource types.
async fn list_resource_types() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": 2,
            "startIndex": 1,
            "itemsPerPage": 2,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "User",
                    "name": "User",
                    "endpoint": "/scim/v2/Users",
                    "description": "User Account",
                    "schema": SCHEMA_USER,
                    "schemaExtensions": [],
                    "meta": {
                        "resourceType": "ResourceType",
                        "location": "/scim/v2/ResourceTypes/User"
                    }
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "Group",
                    "name": "Group",
                    "endpoint": "/scim/v2/Groups",
                    "description": "Group",
                    "schema": SCHEMA_GROUP,
                    "schemaExtensions": [],
                    "meta": {
                        "resourceType": "ResourceType",
                        "location": "/scim/v2/ResourceTypes/Group"
                    }
                }
            ]
        })),
    )
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Builds an `axum::Router<ScimState>` containing all SCIM 2.0 routes.
///
/// The caller must attach the `ScimState` via `.with_state(scim_state)` before
/// merging this router into the main HTTP application.
///
/// ```no_run
/// let scim_state = ScimState::new(principal_store.clone());
/// let app = existing_app.merge(scim::router().with_state(scim_state));
/// ```
pub fn router() -> Router<ScimState> {
    Router::new()
        // Discovery endpoints — no state extraction needed.
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/Schemas", get(list_schemas))
        .route("/scim/v2/ResourceTypes", get(list_resource_types))
        // User CRUD.
        .route(
            "/scim/v2/Users",
            get(users::list_users).post(users::create_user),
        )
        .route(
            "/scim/v2/Users/:id",
            get(users::get_user)
                .put(users::replace_user)
                .patch(users::update_user)
                .delete(users::delete_user),
        )
        // Group CRUD.
        .route(
            "/scim/v2/Groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/scim/v2/Groups/:id",
            get(groups::get_group)
                .put(groups::replace_group)
                .patch(groups::update_group)
                .delete(groups::delete_group),
        )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn test_state() -> ScimState {
        ScimState::new(PrincipalStore::new())
    }

    fn test_app() -> Router {
        router().with_state(test_state())
    }

    #[tokio::test]
    async fn service_provider_config_returns_200() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/ServiceProviderConfig")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_schemas_returns_200() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/Schemas")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_resource_types_returns_200() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/ResourceTypes")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_user_returns_201() {
        let app = test_app();
        let body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "displayName": "Alice"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("content-type", "application/scim+json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_user_missing_username_returns_400() {
        let app = test_app();
        let body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": ""
        });
        let req = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("content-type", "application/scim+json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_missing_user_returns_404() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/Users/does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_group_returns_201() {
        let app = test_app();
        let body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "vault-admins"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/scim/v2/Groups")
            .header("content-type", "application/scim+json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn get_missing_group_returns_404() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/scim/v2/Groups/does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_missing_user_returns_404() {
        let app = test_app();
        let req = Request::builder()
            .method("DELETE")
            .uri("/scim/v2/Users/ghost")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
