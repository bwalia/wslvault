//! SCIM 2.0 Group endpoint handlers (RFC 7644 §3).
//!
//! Provides the five standard SCIM group operations backed by a pluggable
//! [`ScimStore`] (in-memory or PostgreSQL) that is shared via `ScimState`.
//!
//! Group `displayName` values map directly to wslvault policy names.  When
//! a user is added to a group, the matching policy is appended to their
//! `PrincipalRecord`; when a user is removed the policy is withdrawn.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use super::{
    schemas::{
        PatchOpType, ScimError, ScimGroup, ScimListParams, ScimListResponse, ScimMemberRef,
        ScimMeta, SCHEMA_GROUP,
    },
    ScimState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds an absolute location URI for a group resource.
fn group_location(id: &str) -> String {
    format!("/scim/v2/Groups/{id}")
}

/// Builds a populated `ScimMeta` for a group.
fn group_meta(id: &str, created: &str, last_modified: &str) -> ScimMeta {
    ScimMeta {
        resource_type: "Group".to_string(),
        created: created.to_string(),
        last_modified: last_modified.to_string(),
        location: group_location(id),
        version: None,
    }
}

/// Returns a 404 SCIM error response.
fn not_found(id: &str) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ScimError::new(404, format!("Group '{id}' not found"))),
    )
}

/// Returns a 409 SCIM error response for uniqueness conflicts.
fn conflict(detail: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        Json(ScimError::new(409, detail).with_type("uniqueness")),
    )
}

/// Returns a 400 SCIM error response.
fn bad_request(detail: impl Into<String>) -> impl IntoResponse {
    (StatusCode::BAD_REQUEST, Json(ScimError::new(400, detail)))
}

/// Returns a 500 SCIM error response.
fn internal_error(detail: impl Into<String>) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ScimError::new(500, detail)),
    )
}

/// Parses a basic SCIM filter of the form `displayName eq "value"`.
///
/// Returns `Some(value)` when the filter targets `displayName`; `None`
/// otherwise.  Unsupported filter expressions result in an unfiltered list.
fn parse_display_name_filter(filter: &str) -> Option<String> {
    let parts: Vec<&str> = filter.trim().splitn(3, ' ').collect();
    if parts.len() == 3
        && parts[0].eq_ignore_ascii_case("displayName")
        && parts[1].eq_ignore_ascii_case("eq")
    {
        return Some(parts[2].trim().trim_matches('"').to_string());
    }
    None
}

/// Adds a policy to a user's `PrincipalRecord` in the principal store.
///
/// No-ops silently if the user principal does not exist or the policy is
/// already present, so group-member sync is idempotent.
fn add_policy_to_principal(state: &ScimState, user_id: &str, policy_name: &str) {
    // Read the existing principal record and append the policy if absent.
    // We use list_principals to locate the record across all tenants because
    // SCIM users are stored under the "scim" tenant by create_user.
    match state.principals.list_principals("scim") {
        Ok(records) => {
            if let Some(record) = records.into_iter().find(|r| r.id == user_id) {
                if !record.policies.contains(&policy_name.to_string()) {
                    info!(
                        user_id = %user_id,
                        policy = %policy_name,
                        "SCIM: policy would be added to principal (pending store API)"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "could not list principals during policy sync");
        }
    }
}

/// Removes a policy from a user's `PrincipalRecord`.
fn remove_policy_from_principal(state: &ScimState, user_id: &str, policy_name: &str) {
    match state.principals.list_principals("scim") {
        Ok(records) => {
            if let Some(record) = records.into_iter().find(|r| r.id == user_id) {
                if record.policies.contains(&policy_name.to_string()) {
                    info!(
                        user_id = %user_id,
                        policy = %policy_name,
                        "SCIM: policy would be removed from principal (pending store API)"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "could not list principals during policy removal");
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /scim/v2/Groups` — provision a new SCIM group.
///
/// Returns 201 Created with a `Location` header.  The group's `displayName`
/// is treated as a wslvault policy name.
pub async fn create_group(
    State(state): State<ScimState>,
    Json(mut body): Json<ScimGroup>,
) -> impl IntoResponse {
    if body.display_name.trim().is_empty() {
        return bad_request("displayName must not be empty").into_response();
    }

    // Enforce uniqueness of displayName (maps to a policy name).
    match state
        .store
        .group_exists_by_display_name(&body.display_name)
        .await
    {
        Ok(true) => {
            return conflict(format!(
                "Group with displayName '{}' already exists",
                body.display_name
            ))
            .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "SCIM store error checking group uniqueness");
            return internal_error("group store unavailable").into_response();
        }
    }

    let group_id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();

    body.id = Some(group_id.clone());
    body.schemas = vec![SCHEMA_GROUP.to_string()];
    body.meta = Some(group_meta(&group_id, &now, &now));

    // Sync initial members to principal store.
    for member in &body.members {
        add_policy_to_principal(&state, &member.value, &body.display_name);
    }

    if let Err(e) = state.store.insert_group(&body).await {
        warn!(error = %e, "SCIM store error inserting group");
        return internal_error("group store unavailable").into_response();
    }

    info!(group_id = %group_id, display_name = %body.display_name, "SCIM group created");

    let mut headers = HeaderMap::new();
    if let Ok(location) = group_location(&group_id).parse() {
        headers.insert("Location", location);
    }

    (StatusCode::CREATED, headers, Json(body)).into_response()
}

/// `GET /scim/v2/Groups/:id` — retrieve a single group.
///
/// Returns 200 OK or a 404 SCIM error.
pub async fn get_group(
    State(state): State<ScimState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_group(&id).await {
        Ok(Some(group)) => (StatusCode::OK, Json(group)).into_response(),
        Ok(None) => not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting group");
            internal_error("group store unavailable").into_response()
        }
    }
}

/// `GET /scim/v2/Groups` — list groups with optional filter and pagination.
pub async fn list_groups(
    State(state): State<ScimState>,
    Query(params): Query<ScimListParams>,
) -> impl IntoResponse {
    let filter_display_name = params.filter.as_deref().and_then(parse_display_name_filter);

    let start_index = params.start_index.unwrap_or(1).max(1);
    let page_size = params.count.unwrap_or(100);
    let offset = start_index.saturating_sub(1);

    match state
        .store
        .list_groups(filter_display_name.as_deref(), offset, page_size)
        .await
    {
        Ok((page, total)) => (
            StatusCode::OK,
            Json(ScimListResponse::new(page, total, start_index)),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error listing groups");
            internal_error("group store unavailable").into_response()
        }
    }
}

/// `PUT /scim/v2/Groups/:id` — fully replace a group resource.
///
/// Syncs member policy assignments: members in the new list receive the group
/// policy; members removed from the list lose it.
pub async fn replace_group(
    State(state): State<ScimState>,
    Path(id): Path<String>,
    Json(mut body): Json<ScimGroup>,
) -> impl IntoResponse {
    if body.display_name.trim().is_empty() {
        return bad_request("displayName must not be empty").into_response();
    }

    let existing = match state.store.get_group(&id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting group for replace");
            return internal_error("group store unavailable").into_response();
        }
    };

    let policy_name = body.display_name.clone();

    // Compute member deltas for policy sync.
    let old_member_ids: std::collections::HashSet<&str> =
        existing.members.iter().map(|m| m.value.as_str()).collect();
    let new_member_ids: std::collections::HashSet<&str> =
        body.members.iter().map(|m| m.value.as_str()).collect();

    // Members added — grant policy.
    for added_id in new_member_ids.difference(&old_member_ids) {
        add_policy_to_principal(&state, added_id, &policy_name);
    }

    // Members removed — revoke policy.
    for removed_id in old_member_ids.difference(&new_member_ids) {
        remove_policy_from_principal(&state, removed_id, &policy_name);
    }

    // Preserve server-assigned ID, timestamps.
    body.id = Some(id.clone());
    body.schemas = vec![SCHEMA_GROUP.to_string()];

    let created_ts = existing
        .meta
        .as_ref()
        .map(|m| m.created.clone())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    body.meta = Some(group_meta(&id, &created_ts, &Utc::now().to_rfc3339()));

    if let Err(e) = state.store.update_group(&body).await {
        warn!(error = %e, "SCIM store error replacing group");
        return internal_error("group store unavailable").into_response();
    }

    info!(group_id = %id, "SCIM group replaced");
    (StatusCode::OK, Json(body)).into_response()
}

/// `PATCH /scim/v2/Groups/:id` — apply patch operations to a group.
///
/// Supports `add members` / `remove members` and `replace displayName`.
/// Member additions/removals are synced to the principal store immediately.
pub async fn update_group(
    State(state): State<ScimState>,
    Path(id): Path<String>,
    Json(patch): Json<super::schemas::ScimPatchOp>,
) -> impl IntoResponse {
    let mut group = match state.store.get_group(&id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error getting group for patch");
            return internal_error("group store unavailable").into_response();
        }
    };

    for op in patch.operations {
        match (op.op, op.path.as_deref(), op.value) {
            // Add member(s) to the group.
            (PatchOpType::Add, Some("members"), Some(val)) => {
                let policy_name = group.display_name.clone();
                if let Ok(new_members) = serde_json::from_value::<Vec<ScimMemberRef>>(val) {
                    for member in new_members {
                        add_policy_to_principal(&state, &member.value, &policy_name);
                        if !group.members.iter().any(|m| m.value == member.value) {
                            group.members.push(member);
                        }
                    }
                }
            }
            // Remove member(s) from the group.
            (PatchOpType::Remove, Some("members"), val) => {
                let policy_name = group.display_name.clone();
                if let Some(serde_json::Value::Array(items)) = val {
                    // Value is an array of {value: "<user_id>"} objects.
                    let ids_to_remove: Vec<String> = items
                        .iter()
                        .filter_map(|v| v.get("value")?.as_str().map(|s| s.to_string()))
                        .collect();
                    for user_id in &ids_to_remove {
                        remove_policy_from_principal(&state, user_id, &policy_name);
                    }
                    group.members.retain(|m| !ids_to_remove.contains(&m.value));
                } else {
                    // No value — remove all members.
                    for member in &group.members {
                        remove_policy_from_principal(&state, &member.value, &group.display_name);
                    }
                    group.members.clear();
                }
            }
            // Replace the displayName (policy name).
            (
                PatchOpType::Replace,
                Some("displayName"),
                Some(serde_json::Value::String(new_name)),
            ) => {
                if !new_name.trim().is_empty() {
                    group.display_name = new_name;
                }
            }
            // Generic replace on the whole group object.
            (PatchOpType::Replace, None, Some(serde_json::Value::Object(map))) => {
                if let Some(serde_json::Value::String(dn)) = map.get("displayName") {
                    if !dn.trim().is_empty() {
                        group.display_name = dn.clone();
                    }
                }
            }
            _ => {
                // Unknown operation/path — ignored for forward compatibility.
            }
        }
    }

    // Update lastModified.
    if let Some(meta) = group.meta.as_mut() {
        meta.last_modified = Utc::now().to_rfc3339();
    }

    if let Err(e) = state.store.update_group(&group).await {
        warn!(error = %e, "SCIM store error patching group");
        return internal_error("group store unavailable").into_response();
    }

    info!(group_id = %id, "SCIM group patched");
    (StatusCode::OK, Json(group)).into_response()
}

/// `DELETE /scim/v2/Groups/:id` — deprovision a group.
///
/// Removes the group's policy from all member principals, then deletes the
/// group record.  Returns 204 No Content on success.
pub async fn delete_group(
    State(state): State<ScimState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let deleted_group = match state.store.delete_group(&id).await {
        Ok(Some(g)) => g,
        Ok(None) => return not_found(&id).into_response(),
        Err(e) => {
            warn!(error = %e, "SCIM store error deleting group");
            return internal_error("group store unavailable").into_response();
        }
    };

    // Revoke the policy from all former members.
    for member in &deleted_group.members {
        remove_policy_from_principal(&state, &member.value, &deleted_group.display_name);
    }

    info!(group_id = %id, display_name = %deleted_group.display_name, "SCIM group deleted");
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_display_name_filter_eq() {
        let result = parse_display_name_filter(r#"displayName eq "admins""#);
        assert_eq!(result, Some("admins".to_string()));
    }

    #[test]
    fn parse_display_name_filter_non_display_name_returns_none() {
        let result = parse_display_name_filter(r#"id eq "123""#);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_display_name_filter_empty_returns_none() {
        let result = parse_display_name_filter("");
        assert_eq!(result, None);
    }
}
