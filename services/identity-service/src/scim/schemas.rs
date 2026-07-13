//! SCIM 2.0 schema type definitions following RFC 7643.
//!
//! All resource types include the required `schemas` field with the correct
//! SCIM URN.  Field names use SCIM-spec casing (e.g. `userName`, `displayName`)
//! serialised by serde via `rename` attributes to stay consistent with the
//! RFC while keeping Rust field names idiomatic.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SCIM URN constants
// ---------------------------------------------------------------------------

/// Core user schema URN (RFC 7643 §4.1).
pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// Core group schema URN (RFC 7643 §4.2).
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// List response message URN (RFC 7644 §3.4.2).
pub const SCHEMA_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// Error response message URN (RFC 7644 §3.12).
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// Patch operation message URN (RFC 7644 §3.5.2).
pub const SCHEMA_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

/// Structured name sub-attribute for a SCIM User (RFC 7643 §4.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScimName {
    /// Full name formatted for display (e.g. "Ms. Barbara J Jensen, III").
    #[serde(rename = "formatted", skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Family name (surname).
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Given name (first name).
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

/// Multi-valued email address for a SCIM User.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    /// The email address value.
    pub value: String,

    /// Semantic label: "work", "home", etc.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,

    /// Whether this is the primary address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// Reference from a User resource back to one of its group memberships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    /// The unique identifier of the SCIM group.
    pub value: String,

    /// Human-readable display name of the group.
    #[serde(rename = "display", skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,

    /// Absolute URI of the group resource.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

/// Reference from a Group resource to one of its member Users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMemberRef {
    /// The unique identifier of the SCIM user.
    pub value: String,

    /// Human-readable display name of the member.
    #[serde(rename = "display", skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,

    /// Resource type; always "User" for member references.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub member_type: Option<String>,
}

/// Resource metadata included on all SCIM resources (RFC 7643 §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMeta {
    /// Type of this resource ("User" or "Group").
    #[serde(rename = "resourceType")]
    pub resource_type: String,

    /// When the resource was first created (RFC 3339).
    #[serde(rename = "created")]
    pub created: String,

    /// When the resource was last modified (RFC 3339).
    #[serde(rename = "lastModified")]
    pub last_modified: String,

    /// Absolute URI uniquely identifying this resource.
    #[serde(rename = "location")]
    pub location: String,

    /// Opaque version tag for optimistic concurrency (ETag-style).
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Core resource types
// ---------------------------------------------------------------------------

/// SCIM User resource (RFC 7643 §4.1).
///
/// Created and managed via `POST/GET/PUT/PATCH/DELETE /scim/v2/Users`.
/// When a user is provisioned, a corresponding `PrincipalRecord` is created
/// in the wslvault identity-service principal store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    /// Always `["urn:ietf:params:scim:schemas:core:2.0:User"]`.
    pub schemas: Vec<String>,

    /// Server-assigned unique user identifier (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Client-supplied external identifier (stable across updates).
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Unique user name (typically the login name or email-local-part).
    #[serde(rename = "userName")]
    pub user_name: String,

    /// Structured name sub-attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,

    /// Multi-valued email addresses.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub emails: Vec<ScimEmail>,

    /// Human-readable name suitable for display in a UI.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Whether the user account is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    /// Groups this user is a member of (read-only; managed by group handlers).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub groups: Vec<ScimGroupRef>,

    /// Standard resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

impl ScimUser {
    /// Creates a minimal `ScimUser` with the required `schemas` URN.
    pub fn new(user_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![SCHEMA_USER.to_string()],
            id: None,
            external_id: None,
            user_name: user_name.into(),
            name: None,
            emails: Vec::new(),
            display_name: None,
            active: Some(true),
            groups: Vec::new(),
            meta: None,
        }
    }
}

/// SCIM Group resource (RFC 7643 §4.2).
///
/// Group `displayName` maps directly to a wslvault policy name.  When a user
/// is added to a group, the corresponding policy is added to their
/// `PrincipalRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    /// Always `["urn:ietf:params:scim:schemas:core:2.0:Group"]`.
    pub schemas: Vec<String>,

    /// Server-assigned unique group identifier (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Human-readable group name; also used as the wslvault policy name.
    #[serde(rename = "displayName")]
    pub display_name: String,

    /// Members currently in this group.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub members: Vec<ScimMemberRef>,

    /// Standard resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

impl ScimGroup {
    /// Creates a minimal `ScimGroup` with the required `schemas` URN.
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![SCHEMA_GROUP.to_string()],
            id: None,
            display_name: display_name.into(),
            members: Vec::new(),
            meta: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Paginated list response envelope (RFC 7644 §3.4.2).
///
/// The generic parameter `T` is either `ScimUser` or `ScimGroup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimListResponse<T> {
    /// Always `["urn:ietf:params:scim:api:messages:2.0:ListResponse"]`.
    pub schemas: Vec<String>,

    /// Total number of resources matching the query (before pagination).
    #[serde(rename = "totalResults")]
    pub total_results: usize,

    /// 1-based index of the first returned resource.
    #[serde(rename = "startIndex")]
    pub start_index: usize,

    /// Number of resources returned in this page.
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,

    /// The actual resource records for this page.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    /// Constructs a list response from a pre-paginated resource slice.
    pub fn new(resources: Vec<T>, total_results: usize, start_index: usize) -> Self {
        let items_per_page = resources.len();
        Self {
            schemas: vec![SCHEMA_LIST_RESPONSE.to_string()],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// SCIM error response (RFC 7644 §3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimError {
    /// Always `["urn:ietf:params:scim:api:messages:2.0:Error"]`.
    pub schemas: Vec<String>,

    /// HTTP status code as a string (e.g. "404").
    pub status: String,

    /// Human-readable explanation of the error.
    #[serde(rename = "detail", skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Optional SCIM-specific error type (e.g. "uniqueness", "tooMany").
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
}

impl ScimError {
    /// Convenience constructor.
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec![SCHEMA_ERROR.to_string()],
            status: status.to_string(),
            detail: Some(detail.into()),
            scim_type: None,
        }
    }

    /// Returns an error with a `scimType` qualifier.
    pub fn with_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Patch operation types
// ---------------------------------------------------------------------------

/// The three allowed SCIM patch operation types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PatchOpType {
    Add,
    Remove,
    Replace,
}

/// A single operation within a SCIM PATCH request body (RFC 7644 §3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    /// Operation type: "add", "remove", or "replace".
    pub op: PatchOpType,

    /// Optional JSON pointer / attribute path (e.g. "members", "active").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Value to apply.  Omitted for "remove" with a path selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM PATCH request body (RFC 7644 §3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimPatchOp {
    /// Always `["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`.
    pub schemas: Vec<String>,

    /// Ordered list of operations to apply.
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters accepted by SCIM list endpoints.
///
/// Used with axum's `Query` extractor.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScimListParams {
    /// SCIM filter expression (only `userName eq "value"` is currently
    /// supported for users; `displayName eq "value"` for groups).
    pub filter: Option<String>,

    /// 1-based start index for pagination (default: 1).
    #[serde(rename = "startIndex")]
    pub start_index: Option<usize>,

    /// Maximum number of resources to return (default: 100).
    pub count: Option<usize>,
}
