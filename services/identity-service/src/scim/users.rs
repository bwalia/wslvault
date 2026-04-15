//! SCIM 2.0 User endpoint handlers (RFC 7644 §3).
//!
//! Provides the five standard SCIM user operations backed by a pluggable
//! [`ScimStore`] (in-memory or PostgreSQL) that is shared via `ScimState`.
//!
//! When a user is created via SCIM, a matching `PrincipalRecord` is also
//! inserted into the identity-service's `PrincipalStore` so that wslvault
//! policies derived from SCIM group memberships become effective immediately.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;
use wslvault_core::types::principal::AuthMethod;

use crate::store::PrincipalRecord;

use super::{
    schemas::{
        PatchOpType, ScimError, ScimListParams, ScimListResponse, ScimMeta, ScimUser,
        SCHEMA_USER,
    },
    ScimState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds an absolute location URI for a user resource.
fn user_location(id: &str) -> String {
    format!("/scim/v2/Users/{id}")
}

/// Builds a populated `ScimMeta` for a user.
fn user_meta(id: &str, created: &str, last_modified: &str) -> ScimMeta {
    ScimMeta {
        resource_type: "User".to_string(),
        created: created.to_string(),
        last_modified: last_modified.to_string(),
        location: user_location(id),
        version: None,
    }
}

/// Returns a 404 SCIM error response.
fn not_found(id: &str) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ScimError::new(
            404,
            format!("User '{id}' not found"),
        )),
    )
}

/// Returns a 409 SCIM error response for uniqueness conflicts.
fn conflict(detail: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        Json(ScimError::new(409, detail).with_type("uniqueness")),
    )
}

/// Returns a 400 SCIM error response for bad requests.
fn bad_request(detail: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(ScimError::new(400, detail)),
    )
}

/// Returns a 500 SCIM error response for internal errors.
fn internal_error(detail: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ScimError::new(500, detail)),
    )
}

/// Parses a basic SCIM filter of the form `userName eq "value"`.
///
/// Returns `Some(value)` if the filter targets `userName`, `None` otherwise.
/// Unsupported filter expressions cause the list to be returned unfiltered
/// so that clients relying on unsupported filters see all resources rather
/// than an opaque error (permissive degradation).
fn parse_username_filter(filter: &str) -> Option<String> {
    // Normalise and split on whitespace: ["userName", "eq", "\"value\""]
    let parts: Vec<&str> = filter.trim().splitn(3, ' ').collect();
    if parts.len() == 3
        && parts[0].eq_ignore_ascii_case("userName")
        && parts[1].eq_ignore_ascii_case("eq")
    {
        // Strip surrounding quotes from the value.
        let raw = parts[2].trim().trim_matches('"').to_string();
        return Some(raw);
    }
    None
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /scim/v2/Users` — provision a new SCIM user.
///
/// Returns 201 Created with a `Location` header and the full `ScimUser`
/// resource in the response body.  Also creates a matching `PrincipalRecord`
/// in the principal store so that wslvault policy evaluation works for the
/// new user.
pub async fn create_user(
    State(state): State<ScimState>,
    Json(mut body): Json<ScimUser>,
) -> impl IntoResponse {
    // Validate required fields.
    if body.user_name.trim().is_empty() {
        return bad_request("userName must not be empty").into_response();
    }

    // Enforce uniqueness of userName across the store.
    match state.store.user_exists_by_username(&body.user_name).await {
        Ok(true) => {
            return conflict(format!(
                "User with userName '{}' already exists",
                body.user_name
            ))
            .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "SCIM store error checking username uniqueness");
            return internal_error("user store unavailable").into_response();
        }
    }

    let user_id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();

    // Ensure the schemas field is correctly populated even if the client
    // omitted it (lenient provisioning).
    if body.schemas.is_empty() {
        body.schemas = vec![SCHEMA_USER.to_string()];
    }

    body.id = Some(user_id.clone());
    body.meta = Some(user_meta(&user_id, &now, &now));

    // Also provision a PrincipalRecord so wslvault can authenticate this user.
    let display = body
        .display_name
        .clone()
        .unwrap_or_else(|| body.user_name.clone());

    let principal = PrincipalRecord {
        id: user_id.clone(),
        // SCIM users are provisioned into a shared "scim" tenant namespace.
        // A future extension can accept a tenant_id header.
        tenant_id: "scim".to_string(),
        display_name: display,
        auth_method: AuthMethod::Token,
        // Initial policies are derived from current group memberships;
        // at creation time there are none yet.
        policies: Vec::new(),
        created_at: Utc::now(),
    };

    if let Err(e) = state.principals.create_principal(principal) {
        // Log but do not fail — the SCIM user is still stored.  Conflicts
        // indicate the principal already exists (idempotent provisioning).
        warn!(user_id = %user_id, error = %e, "could not create principal record for SCIM user");
    }

    if let Err(e) = state.store.insert_user(&body).await {
        warn!(error = %e, "SCIM store error inserting user");
        return internal_error("user store unavailable").into_response();
    }

    info!(user_id = %user_id, user_name = %body.user_name, "SCIM user created");

    let mut headers = HeaderMap::new();
    if let Ok(location) = user_location(&user_id).parse() {
        headers.insert("Location", location);
    }

    (StatusCode::CREATED, headers, Json(body)).into_response()
}

/// `GET /scim/v2/Users/:id` — retrieve a single user by its server-assigned ID.
///
/// Returns 200 OK with the `ScimUser` resource, or a 404 SCIM error if no
/// user with that ID exists.
pub async fn get_user(
    State(state): State<ScimState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_user(&id).await {
        Ok(Some(user)) => (StatusCode::OK, Json(user)).into_response(),
        Ok(None) => not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting user");
            internal_error("user store unavailable").into_response()
        }
    }
}

/// `GET /scim/v2/Users` — list users, with optional filter and pagination.
///
/// Supports the `filter` query parameter for `userName eq "value"` expressions
/// and `startIndex` / `count` for pagination per RFC 7644 §3.4.2.
pub async fn list_users(
    State(state): State<ScimState>,
    Query(params): Query<ScimListParams>,
) -> impl IntoResponse {
    // Parse optional userName filter.
    let filter_username = params
        .filter
        .as_deref()
        .and_then(parse_username_filter);

    let start_index = params.start_index.unwrap_or(1).max(1);
    let page_size = params.count.unwrap_or(100);
    let offset = start_index.saturating_sub(1);

    match state
        .store
        .list_users(filter_username.as_deref(), offset, page_size)
        .await
    {
        Ok((page, total)) => (
            StatusCode::OK,
            Json(ScimListResponse::new(page, total, start_index)),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error listing users");
            internal_error("user store unavailable").into_response()
        }
    }
}

/// `PUT /scim/v2/Users/:id` — fully replace a user resource.
///
/// Returns 200 OK with the updated user, or 404 if the user does not exist.
pub async fn replace_user(
    State(state): State<ScimState>,
    Path(id): Path<String>,
    Json(mut body): Json<ScimUser>,
) -> impl IntoResponse {
    if body.user_name.trim().is_empty() {
        return bad_request("userName must not be empty").into_response();
    }

    let existing = match state.store.get_user(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting user for replace");
            return internal_error("user store unavailable").into_response();
        }
    };

    // Preserve the server-assigned id and creation timestamp.
    body.id = Some(id.clone());
    body.schemas = vec![SCHEMA_USER.to_string()];

    let created_ts = existing
        .meta
        .as_ref()
        .map(|m| m.created.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let now = Utc::now().to_rfc3339();
    body.meta = Some(user_meta(&id, &created_ts, &now));

    // Preserve group membership (managed by group handlers only).
    body.groups = existing.groups;

    if let Err(e) = state.store.update_user(&body).await {
        warn!(error = %e, "SCIM store error replacing user");
        return internal_error("user store unavailable").into_response();
    }

    info!(user_id = %id, "SCIM user replaced");
    (StatusCode::OK, Json(body)).into_response()
}

/// `PATCH /scim/v2/Users/:id` — apply a set of SCIM patch operations.
///
/// Supported operations:
/// - `replace` on `active`, `displayName`, or the top-level user object.
/// - `add` / `replace` on `emails` / `name` sub-attributes.
/// - `remove` on `emails`.
///
/// Returns 200 OK with the patched resource, or 404 if the user is missing.
pub async fn update_user(
    State(state): State<ScimState>,
    Path(id): Path<String>,
    Json(patch): Json<super::schemas::ScimPatchOp>,
) -> impl IntoResponse {
    let mut user = match state.store.get_user(&id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting user for patch");
            return internal_error("user store unavailable").into_response();
        }
    };

    for op in patch.operations {
        match op.op {
            PatchOpType::Replace | PatchOpType::Add => {
                apply_user_patch(&mut user, op.path.as_deref(), op.value);
            }
            PatchOpType::Remove => {
                if let Some(path) = op.path.as_deref() {
                    apply_user_remove(&mut user, path);
                }
            }
        }
    }

    // Update lastModified timestamp.
    if let Some(meta) = user.meta.as_mut() {
        meta.last_modified = Utc::now().to_rfc3339();
    }

    if let Err(e) = state.store.update_user(&user).await {
        warn!(error = %e, "SCIM store error patching user");
        return internal_error("user store unavailable").into_response();
    }

    info!(user_id = %id, "SCIM user patched");
    (StatusCode::OK, Json(user)).into_response()
}

/// Applies an `add` or `replace` patch operation to a mutable user.
fn apply_user_patch(
    user: &mut ScimUser,
    path: Option<&str>,
    value: Option<serde_json::Value>,
) {
    let Some(val) = value else { return };

    match path {
        None => {
            // No path means the value is a partial user object; merge fields.
            if let serde_json::Value::Object(map) = val {
                if let Some(active) = map.get("active").and_then(|v| v.as_bool()) {
                    user.active = Some(active);
                }
                if let Some(dn) = map.get("displayName").and_then(|v| v.as_str()) {
                    user.display_name = Some(dn.to_string());
                }
                if let Some(un) = map.get("userName").and_then(|v| v.as_str()) {
                    if !un.trim().is_empty() {
                        user.user_name = un.to_string();
                    }
                }
            }
        }
        Some("active") => {
            if let Some(active) = val.as_bool() {
                user.active = Some(active);
            }
        }
        Some("displayName") => {
            if let Some(dn) = val.as_str() {
                user.display_name = Some(dn.to_string());
            }
        }
        Some("userName") => {
            if let Some(un) = val.as_str() {
                if !un.trim().is_empty() {
                    user.user_name = un.to_string();
                }
            }
        }
        Some("name") => {
            if let Ok(name) = serde_json::from_value(val) {
                user.name = Some(name);
            }
        }
        Some("emails") => {
            if let Ok(emails) = serde_json::from_value(val) {
                user.emails = emails;
            }
        }
        _ => {
            // Unknown path — ignored to maintain forward compatibility.
        }
    }
}

/// Applies a `remove` patch operation to a mutable user.
fn apply_user_remove(user: &mut ScimUser, path: &str) {
    match path {
        "emails" => user.emails.clear(),
        "active" => user.active = None,
        "displayName" => user.display_name = None,
        "name" => user.name = None,
        _ => {}
    }
}

/// `DELETE /scim/v2/Users/:id` — deprovision a user.
///
/// Returns 204 No Content on success, or 404 if the user does not exist.
pub async fn delete_user(
    State(state): State<ScimState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.delete_user(&id).await {
        Ok(true) => {
            info!(user_id = %id, "SCIM user deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error deleting user");
            internal_error("user store unavailable").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_username_filter_eq() {
        let result = parse_username_filter(r#"userName eq "alice@example.com""#);
        assert_eq!(result, Some("alice@example.com".to_string()));
    }

    #[test]
    fn parse_username_filter_case_insensitive_operator() {
        let result = parse_username_filter(r#"userName EQ "bob""#);
        assert_eq!(result, Some("bob".to_string()));
    }

    #[test]
    fn parse_username_filter_non_username_returns_none() {
        let result = parse_username_filter(r#"emails.value eq "a@b.com""#);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_username_filter_empty_returns_none() {
        let result = parse_username_filter("");
        assert_eq!(result, None);
    }
}
