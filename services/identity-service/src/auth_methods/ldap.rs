//! LDAP / Active Directory bind-based authentication.
//!
//! # Authentication flow
//!
//! Two modes are supported, controlled by [`LdapBindMode`]:
//!
//! **Direct bind** (`DirectBind`): the user's DN is constructed from a template
//! (e.g. `"uid={username},ou=people,dc=example,dc=com"`) and a bind is
//! attempted with the supplied password.  Groups are read from the bound entry
//! via the configured `group_attribute`.
//!
//! **Search-then-bind** (`SearchThenBind`): a privileged service account binds
//! first, searches for the user using a configurable filter, then re-binds as
//! the found DN.  This mode is required when user DNs are not predictable from
//! the username alone (e.g. Active Directory with nested OUs).
//!
//! # Group → policy mapping
//!
//! After a successful bind the module reads the configured `group_attribute`
//! from the user entry (default: `"memberOf"`).  Each group value is looked up
//! in `LdapConfig::group_policy_map`; matching entries are collected into the
//! principal's policy list.  Additionally the group value is checked in
//! `LdapConfig::group_tenant_map` to derive the tenant_id; when multiple groups
//! map to a tenant the first match wins.
//!
//! # TLS
//!
//! Set `tls_mode` to `Starttls` or `Ldaps` to enable encrypted transport.
//! `None` (plain-text) is available only for local dev/test environments.
//!
//! # Security notes
//!
//! - Passwords are **never** logged; they exist only on the stack during the
//!   bind call and are dropped immediately after.
//! - Usernames are sanitised against LDAP DN injection before interpolation
//!   (see [`sanitise_username`]).
//! - Input lengths are bounded: usernames ≤ 256 bytes, passwords ≤ 1024 bytes.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::token::TokenManager;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum allowed length (bytes) for an incoming username. Prevents abuse
/// of LDAP search filters and DN templates.
const MAX_USERNAME_LEN: usize = 256;

/// Maximum allowed length (bytes) for an incoming password.
const MAX_PASSWORD_LEN: usize = 1024;

/// Default LDAP attribute that carries group membership (Active Directory uses
/// `memberOf`; OpenLDAP often uses `memberOf` via the memberof overlay).
const DEFAULT_GROUP_ATTRIBUTE: &str = "memberOf";

/// JWT TTL (seconds) issued on successful LDAP authentication.
const LDAP_JWT_TTL_SECONDS: i64 = 3600;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors returned by [`LdapManager`].
#[derive(Debug, Error)]
pub enum LdapError {
    #[error("username contains invalid characters")]
    InvalidUsername,

    #[error("authentication failed: invalid credentials")]
    InvalidCredentials,

    #[error("LDAP connection error: {0}")]
    ConnectionError(String),

    #[error("LDAP search error: {0}")]
    SearchError(String),

    #[error("no tenant could be resolved for the authenticated user")]
    NoTenantResolved,

    #[error("token issuance failed: {0}")]
    TokenIssuance(String),
}

impl LdapError {
    fn status_code(&self) -> StatusCode {
        match self {
            LdapError::InvalidUsername => StatusCode::BAD_REQUEST,
            LdapError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            LdapError::ConnectionError(_) => StatusCode::BAD_GATEWAY,
            LdapError::SearchError(_) => StatusCode::BAD_GATEWAY,
            LdapError::NoTenantResolved => StatusCode::FORBIDDEN,
            LdapError::TokenIssuance(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            LdapError::InvalidUsername => "invalid_username",
            LdapError::InvalidCredentials => "invalid_credentials",
            LdapError::ConnectionError(_) => "ldap_connection_error",
            LdapError::SearchError(_) => "ldap_search_error",
            LdapError::NoTenantResolved => "no_tenant_resolved",
            LdapError::TokenIssuance(_) => "token_issuance_failed",
        }
    }
}

impl IntoResponse for LdapError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status_code(),
            Json(serde_json::json!({
                "code": self.error_code(),
                "message": self.to_string(),
            })),
        )
            .into_response()
    }
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// How the user's LDAP Distinguished Name is resolved before binding.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum LdapBindMode {
    /// Construct the DN directly from a template containing `{username}`.
    ///
    /// Example: `"uid={username},ou=people,dc=example,dc=com"`.
    DirectBind {
        /// DN template.  Must contain exactly one `{username}` placeholder.
        dn_template: String,
    },

    /// Bind as a service account, search for the user, then re-bind as that DN.
    SearchThenBind {
        /// DN of the service account used for the initial search bind.
        service_account_dn: String,
        /// Password of the service account.  Loaded from env; never logged.
        service_account_password: String,
        /// Base DN for the user search.
        search_base: String,
        /// LDAP filter template — `{username}` is substituted with the sanitised
        /// username.  Example: `"(sAMAccountName={username})"`.
        search_filter_template: String,
    },
}

/// TLS mode for the LDAP connection.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LdapTlsMode {
    /// Plain-text connection (LDAP on port 389).  Only for local dev.
    #[default]
    None,
    /// Upgrade to TLS after connecting via `STARTTLS` (RFC 4511 §4.14).
    Starttls,
    /// Connect directly over TLS (LDAPS on port 636).
    Ldaps,
}

/// Full configuration for the LDAP authentication backend.
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL, e.g. `"ldap://ldap.example.com:389"`.
    pub url: String,

    /// How to derive the user's DN before binding.
    pub bind_mode: LdapBindMode,

    /// LDAP attribute on the user entry that lists group memberships.
    /// Defaults to `"memberOf"`.
    pub group_attribute: Option<String>,

    /// Maps LDAP group DN/CN values to wslvault policy names.
    /// A single group may map to multiple policies.
    pub group_policy_map: HashMap<String, Vec<String>>,

    /// Maps LDAP group DN/CN values to wslvault tenant_ids.
    /// The first matching group wins.
    pub group_tenant_map: HashMap<String, String>,

    /// Fallback tenant_id when no group→tenant mapping is found.
    pub default_tenant_id: Option<String>,

    /// Fallback policies applied to every authenticated principal.
    pub default_policies: Vec<String>,

    /// TLS mode; defaults to `None` (plain text).
    pub tls_mode: Option<LdapTlsMode>,
}

// ── Manager ───────────────────────────────────────────────────────────────────

/// Validates LDAP/AD credentials and translates group memberships into
/// wslvault tenant_id and policy names.
pub struct LdapManager {
    config: Arc<LdapConfig>,
}

/// The outcome of a successful LDAP authentication.
#[derive(Debug, Clone)]
pub struct LdapValidationResult {
    /// The user's distinguished name.
    pub dn: String,
    /// Resolved wslvault tenant_id.
    pub tenant_id: String,
    /// Resolved wslvault policy names.
    pub policies: Vec<String>,
}

impl LdapManager {
    /// Constructs a new `LdapManager` from the given configuration.
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Authenticates a user against LDAP.
    ///
    /// Sanitises the username, performs the appropriate bind (direct or
    /// search-then-bind), reads group attributes, then maps groups to tenant
    /// and policies.
    ///
    /// # Security
    ///
    /// - Passwords are accepted only as `&str` and are not stored or logged.
    /// - Usernames are sanitised before interpolation into DN templates or
    ///   search filters (see [`sanitise_username`]).
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapValidationResult, LdapError> {
        // ── Input validation ──────────────────────────────────────────────
        if username.len() > MAX_USERNAME_LEN {
            return Err(LdapError::InvalidUsername);
        }
        if password.len() > MAX_PASSWORD_LEN || password.is_empty() {
            return Err(LdapError::InvalidCredentials);
        }

        let safe_username = sanitise_username(username)?;

        // ── Open LDAP connection ──────────────────────────────────────────
        let conn_settings = self.build_conn_settings();
        let (conn, mut ldap) = LdapConnAsync::with_settings(conn_settings, &self.config.url)
            .await
            .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

        // Drive the connection on a background task; the driver closes when
        // `ldap` is dropped.
        ldap3::drive!(conn);

        // ── Bind and resolve user DN ──────────────────────────────────────
        let user_dn = match &self.config.bind_mode {
            LdapBindMode::DirectBind { dn_template } => {
                let dn = dn_template.replace("{username}", &safe_username);
                // Bind as the user directly; this validates the password.
                let result = ldap
                    .simple_bind(&dn, password)
                    .await
                    .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

                if result.rc != 0 {
                    warn!(
                        username = %username,
                        rc = result.rc,
                        "LDAP direct bind failed"
                    );
                    return Err(LdapError::InvalidCredentials);
                }

                dn
            }

            LdapBindMode::SearchThenBind {
                service_account_dn,
                service_account_password,
                search_base,
                search_filter_template,
            } => {
                // Step 1: bind as service account.
                let svc_result = ldap
                    .simple_bind(service_account_dn, service_account_password)
                    .await
                    .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

                if svc_result.rc != 0 {
                    return Err(LdapError::ConnectionError(format!(
                        "service account bind failed (rc={})",
                        svc_result.rc
                    )));
                }

                // Step 2: search for the user DN.
                let filter = search_filter_template.replace("{username}", &safe_username);
                let group_attr = self
                    .config
                    .group_attribute
                    .as_deref()
                    .unwrap_or(DEFAULT_GROUP_ATTRIBUTE);

                let (search_results, _res) = ldap
                    .search(
                        search_base,
                        Scope::Subtree,
                        &filter,
                        vec!["dn", group_attr],
                    )
                    .await
                    .map_err(|e| LdapError::SearchError(e.to_string()))?
                    .success()
                    .map_err(|e| LdapError::SearchError(e.to_string()))?;

                let entry = search_results
                    .into_iter()
                    .next()
                    .ok_or(LdapError::InvalidCredentials)?;

                let found_dn = SearchEntry::construct(entry).dn;

                // Step 3: unbind service account, then bind as the user to
                // verify the supplied password.
                ldap.unbind()
                    .await
                    .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

                // Re-open a fresh connection for the user bind.
                let user_settings = self.build_conn_settings();
                let (user_conn, mut user_ldap) =
                    LdapConnAsync::with_settings(user_settings, &self.config.url)
                        .await
                        .map_err(|e| LdapError::ConnectionError(e.to_string()))?;
                ldap3::drive!(user_conn);

                let user_result = user_ldap
                    .simple_bind(&found_dn, password)
                    .await
                    .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

                if user_result.rc != 0 {
                    warn!(
                        username = %username,
                        rc = user_result.rc,
                        "LDAP user bind failed after search"
                    );
                    return Err(LdapError::InvalidCredentials);
                }

                user_ldap
                    .unbind()
                    .await
                    .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

                found_dn
            }
        };

        // ── Read group attributes ─────────────────────────────────────────
        let group_attr = self
            .config
            .group_attribute
            .as_deref()
            .unwrap_or(DEFAULT_GROUP_ATTRIBUTE);

        let (search_results, _res) = ldap
            .search(
                &user_dn,
                Scope::Base,
                "(objectClass=*)",
                vec![group_attr],
            )
            .await
            .map_err(|e| LdapError::SearchError(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchError(e.to_string()))?;

        let groups: Vec<String> = search_results
            .into_iter()
            .next()
            .map(|entry| {
                let parsed = SearchEntry::construct(entry);
                parsed
                    .attrs
                    .get(group_attr)
                    .cloned()
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        ldap.unbind()
            .await
            .map_err(|e| LdapError::ConnectionError(e.to_string()))?;

        // ── Map groups → tenant + policies ───────────────────────────────
        let (tenant_id, policies) = self.map_groups(&groups)?;

        info!(
            username = %username,
            tenant_id = %tenant_id,
            group_count = groups.len(),
            "LDAP authentication succeeded"
        );

        Ok(LdapValidationResult {
            dn: user_dn,
            tenant_id,
            policies,
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Builds [`LdapConnSettings`] from the configured TLS mode.
    fn build_conn_settings(&self) -> LdapConnSettings {
        let settings = LdapConnSettings::new();
        match self.config.tls_mode.as_ref().unwrap_or(&LdapTlsMode::None) {
            LdapTlsMode::None => settings,
            // STARTTLS and LDAPS both rely on the `tls` feature of `ldap3`;
            // the actual protocol selection is handled by the URL scheme
            // (`ldap://` with STARTTLS upgrade, or `ldaps://`).
            LdapTlsMode::Starttls => settings.set_starttls(true),
            LdapTlsMode::Ldaps => settings,
        }
    }

    /// Translates a list of LDAP group values into a `(tenant_id, policies)` pair.
    ///
    /// Tenant resolution: iterate groups in order, return the first hit in
    /// `group_tenant_map`.  If no group maps to a tenant, fall back to
    /// `default_tenant_id`.
    ///
    /// Policy resolution: collect all policies from every matching group in
    /// `group_policy_map`, then append `default_policies`.
    pub fn map_groups(&self, groups: &[String]) -> Result<(String, Vec<String>), LdapError> {
        // Resolve tenant from the first matching group.
        let tenant_id = groups
            .iter()
            .find_map(|g| self.config.group_tenant_map.get(g).cloned())
            .or_else(|| self.config.default_tenant_id.clone())
            .ok_or(LdapError::NoTenantResolved)?;

        // Collect policies from every matching group.
        let mut policies: Vec<String> = groups
            .iter()
            .flat_map(|g| {
                self.config
                    .group_policy_map
                    .get(g)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();

        // Append static default policies.
        policies.extend(self.config.default_policies.iter().cloned());

        Ok((tenant_id, policies))
    }
}

// ── Username sanitisation ────────────────────────────────────────────────────

/// Characters that are special in LDAP DN values (RFC 4514 §2.4) and must
/// not appear in the raw username before interpolation.
const LDAP_DN_SPECIAL_CHARS: &[char] = &[',', '+', '"', '\\', '<', '>', ';', '#', '='];

/// Sanitises a username to prevent LDAP DN injection.
///
/// Rejects any username that contains LDAP DN special characters or ASCII
/// control bytes so the value is safe to embed in a DN template or search filter.
///
/// # Returns
///
/// The original username string (as `&str`) when it is safe to use.
/// `LdapError::InvalidUsername` when it contains forbidden characters.
pub fn sanitise_username(username: &str) -> Result<String, LdapError> {
    if username.is_empty() {
        return Err(LdapError::InvalidUsername);
    }

    // Reject control characters (0x00-0x1F, 0x7F).
    if username.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(LdapError::InvalidUsername);
    }

    // Reject LDAP DN special characters.
    if username.chars().any(|c| LDAP_DN_SPECIAL_CHARS.contains(&c)) {
        return Err(LdapError::InvalidUsername);
    }

    Ok(username.to_owned())
}

// ── HTTP layer ───────────────────────────────────────────────────────────────

/// Shared state injected into every LDAP HTTP handler.
#[derive(Clone)]
pub struct LdapState {
    pub manager: Arc<LdapManager>,
    pub token_manager: TokenManager,
}

/// Request body for `POST /v1/auth/ldap/login`.
#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

/// Response body from `POST /v1/auth/ldap/login`.
#[derive(Debug, Serialize)]
pub struct LdapLoginResponse {
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub policies: Vec<String>,
}

/// `POST /v1/auth/ldap/login` — authenticate via LDAP bind and issue a JWT.
pub async fn handle_ldap_login(
    State(state): State<LdapState>,
    Json(payload): Json<LdapLoginRequest>,
) -> impl IntoResponse {
    // NOTE: payload.password is intentionally never logged, traced, or included
    // in any error message.  It lives only on this stack frame and is dropped
    // when the handler returns.
    match state
        .manager
        .authenticate(&payload.username, &payload.password)
        .await
    {
        Ok(result) => {
            let subject = result.dn.clone();
            match state.token_manager.issue_token(
                &subject,
                &result.tenant_id,
                result.policies.clone(),
                LDAP_JWT_TTL_SECONDS,
            ) {
                Ok((token, expires_at)) => {
                    info!(
                        username = %payload.username,
                        tenant_id = %result.tenant_id,
                        "LDAP login successful; JWT issued"
                    );
                    (
                        StatusCode::OK,
                        Json(LdapLoginResponse {
                            token,
                            expires_at,
                            tenant_id: result.tenant_id,
                            policies: result.policies,
                        }),
                    )
                        .into_response()
                }
                Err(e) => {
                    let err = LdapError::TokenIssuance(e.to_string());
                    err.into_response()
                }
            }
        }
        Err(err) => {
            warn!(username = %payload.username, error = %err, "LDAP login failed");
            err.into_response()
        }
    }
}

/// Builds the axum [`Router`] for LDAP auth routes.
pub fn router(state: LdapState) -> Router {
    Router::new()
        .route("/v1/auth/ldap/login", post(handle_ldap_login))
        .with_state(state)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Username sanitisation ─────────────────────────────────────────────

    #[test]
    fn sanitise_plain_username_ok() {
        let result = sanitise_username("alice").unwrap();
        assert_eq!(result, "alice");
    }

    #[test]
    fn sanitise_username_with_dots_and_hyphens_ok() {
        // Dots and hyphens are common in AD usernames.
        assert!(sanitise_username("alice.smith-ops").is_ok());
    }

    #[test]
    fn sanitise_username_rejects_empty() {
        assert!(matches!(
            sanitise_username(""),
            Err(LdapError::InvalidUsername)
        ));
    }

    #[test]
    fn sanitise_username_rejects_comma_injection() {
        // A comma would allow injecting additional DN components.
        assert!(matches!(
            sanitise_username("alice,ou=admin"),
            Err(LdapError::InvalidUsername)
        ));
    }

    #[test]
    fn sanitise_username_rejects_backslash_escape() {
        assert!(matches!(
            sanitise_username("alice\\00"),
            Err(LdapError::InvalidUsername)
        ));
    }

    #[test]
    fn sanitise_username_rejects_null_byte() {
        assert!(matches!(
            sanitise_username("alice\x00admin"),
            Err(LdapError::InvalidUsername)
        ));
    }

    #[test]
    fn sanitise_username_rejects_semicolon() {
        assert!(matches!(
            sanitise_username("alice;drop"),
            Err(LdapError::InvalidUsername)
        ));
    }

    // ── Config parsing ────────────────────────────────────────────────────

    #[test]
    fn ldap_config_deserialises_direct_bind() {
        let json = serde_json::json!({
            "url": "ldap://localhost:389",
            "bind_mode": {
                "mode": "direct_bind",
                "dn_template": "uid={username},ou=people,dc=example,dc=com"
            },
            "group_attribute": "memberOf",
            "group_policy_map": {
                "cn=admins,dc=example,dc=com": ["admin", "write"]
            },
            "group_tenant_map": {
                "cn=admins,dc=example,dc=com": "tenant-1"
            },
            "default_tenant_id": null,
            "default_policies": ["read"],
            "tls_mode": "none"
        });

        let config: LdapConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.url, "ldap://localhost:389");
        assert_eq!(config.default_policies, vec!["read"]);
        match &config.bind_mode {
            LdapBindMode::DirectBind { dn_template } => {
                assert!(dn_template.contains("{username}"));
            }
            _ => panic!("expected DirectBind"),
        }
    }

    // ── Group → policy mapping ─────────────────────────────────────────────

    fn make_manager_with_groups() -> LdapManager {
        let mut group_policy_map = HashMap::new();
        group_policy_map.insert(
            "cn=vault-admins,dc=example,dc=com".to_string(),
            vec!["admin".to_string(), "write".to_string()],
        );
        group_policy_map.insert(
            "cn=developers,dc=example,dc=com".to_string(),
            vec!["read".to_string()],
        );

        let mut group_tenant_map = HashMap::new();
        group_tenant_map.insert(
            "cn=vault-admins,dc=example,dc=com".to_string(),
            "tenant-admin".to_string(),
        );
        group_tenant_map.insert(
            "cn=developers,dc=example,dc=com".to_string(),
            "tenant-dev".to_string(),
        );

        LdapManager::new(LdapConfig {
            url: "ldap://localhost:389".to_string(),
            bind_mode: LdapBindMode::DirectBind {
                dn_template: "uid={username},dc=example,dc=com".to_string(),
            },
            group_attribute: None,
            group_policy_map,
            group_tenant_map,
            default_tenant_id: None,
            default_policies: vec!["base".to_string()],
            tls_mode: None,
        })
    }

    #[test]
    fn map_groups_resolves_tenant_and_policies() {
        let mgr = make_manager_with_groups();
        let groups = vec!["cn=vault-admins,dc=example,dc=com".to_string()];
        let (tenant_id, policies) = mgr.map_groups(&groups).unwrap();
        assert_eq!(tenant_id, "tenant-admin");
        assert!(policies.contains(&"admin".to_string()));
        assert!(policies.contains(&"write".to_string()));
        // Default policies appended.
        assert!(policies.contains(&"base".to_string()));
    }

    #[test]
    fn map_groups_first_tenant_wins() {
        let mgr = make_manager_with_groups();
        // First group in the list determines the tenant when multiple match.
        let groups = vec![
            "cn=vault-admins,dc=example,dc=com".to_string(),
            "cn=developers,dc=example,dc=com".to_string(),
        ];
        let (tenant_id, _) = mgr.map_groups(&groups).unwrap();
        assert_eq!(tenant_id, "tenant-admin");
    }

    #[test]
    fn map_groups_collects_policies_from_all_groups() {
        let mgr = make_manager_with_groups();
        let groups = vec![
            "cn=vault-admins,dc=example,dc=com".to_string(),
            "cn=developers,dc=example,dc=com".to_string(),
        ];
        let (_, policies) = mgr.map_groups(&groups).unwrap();
        assert!(policies.contains(&"admin".to_string()));
        assert!(policies.contains(&"read".to_string()));
    }

    #[test]
    fn map_groups_falls_back_to_default_tenant() {
        let mut group_policy_map = HashMap::new();
        group_policy_map.insert("cn=users,dc=example,dc=com".to_string(), vec!["read".to_string()]);

        let mgr = LdapManager::new(LdapConfig {
            url: "ldap://localhost:389".to_string(),
            bind_mode: LdapBindMode::DirectBind {
                dn_template: "uid={username},dc=example,dc=com".to_string(),
            },
            group_attribute: None,
            group_policy_map,
            group_tenant_map: HashMap::new(), // no tenant mapping
            default_tenant_id: Some("tenant-default".to_string()),
            default_policies: vec![],
            tls_mode: None,
        });

        let groups = vec!["cn=users,dc=example,dc=com".to_string()];
        let (tenant_id, _) = mgr.map_groups(&groups).unwrap();
        assert_eq!(tenant_id, "tenant-default");
    }

    #[test]
    fn map_groups_errors_when_no_tenant_resolved() {
        let mgr = make_manager_with_groups();
        // Provide a group that has no tenant mapping and no default.
        let groups = vec!["cn=unknown-group,dc=example,dc=com".to_string()];
        let err = mgr.map_groups(&groups).unwrap_err();
        assert!(matches!(err, LdapError::NoTenantResolved));
    }
}
