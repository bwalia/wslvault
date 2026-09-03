//! Tenant invitations — issue, inspect, redeem.
//!
//! # The gap this closes
//!
//! Creating a tenant produced a row with no API key and no way for anyone at
//! that organisation to obtain one; the only route in was for an operator to
//! mint a key and hand it over out of band. An operator now invites an address
//! instead, and the recipient mints their own first key by redeeming the link.
//!
//! # Route authority
//!
//! | Route | Who |
//! |---|---|
//! | `POST /v1/tenants/:id/invitations` | administrator ([`require_admin`]) |
//! | `GET /v1/tenants/:id/invitations` | administrator |
//! | `DELETE /v1/invitations/:id` | administrator |
//! | `GET /v1/invitations/:token` | **public** |
//! | `POST /v1/invitations/:token/accept` | **public** |
//!
//! The last two must be public: the recipient has no credential yet — obtaining
//! one is the entire point. They are safe to be, because the token is 256 bits
//! of CSPRNG output looked up by hash, single-use, and expiring. Nothing about
//! them is enumerable, and holding one grants exactly what the issuing operator
//! chose.
//!
//! # Why the admin routes are not additionally tenant-scoped
//!
//! They briefly were: a caller whose JWT named tenant A was refused when
//! inviting into tenant B. That was removed, because it was incoherent rather
//! than protective.
//!
//! `tenant_handlers` does not scope at all — it never reads [`AdminIdentity`],
//! so the same credential can create *and delete* any tenant in the deployment.
//! Scoping invitations alone produced a state where an operator could create a
//! tenant through the UI and then be refused permission to invite anyone into
//! it, which is exactly what happened the first time someone used the feature.
//!
//! It was also not buying anything. Every caller here has already satisfied
//! [`require_admin`], which is the authorisation boundary, and issuing an
//! invitation is strictly weaker than the tenant deletion that same caller can
//! already perform. A guard that blocks the legitimate path while leaving the
//! more damaging one open is theatre.
//!
//! The genuine gap is upstream and known: `require_admin` cannot distinguish a
//! platform administrator from a tenant's own administrator while
//! `VAULT_ADMIN_POLICY` is pinned to `"admin"` in the chart. Fixing that — a
//! migration granting `wslvault:platform-admin` to operator keys, then dropping
//! the pin — is what makes per-tenant scoping expressible here. Re-adding a
//! scope check before then only breaks the working path again.
//!
//! [`require_admin`]: crate::api_keys::require_admin
//! [`AdminIdentity`]: crate::api_keys::AdminIdentity

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use wslvault_storage::invitation_store::{self, Invitation, RedeemFailure};
use wslvault_storage::pool::DbPool;

use crate::api_keys::{AdminIdentity, ApiKeyManager};
use crate::mailer::Mailer;

/// How long an invitation is good for when the caller does not say.
const DEFAULT_TTL_HOURS: i64 = 72;

/// Ceiling on the requested lifetime. An invitation is a bearer credential in
/// someone's inbox; a month-long one is a month-long window for whoever else
/// reads that inbox.
const MAX_TTL_HOURS: i64 = 24 * 14;

/// Bytes of randomness in a token. 256 bits, so the hash lookup cannot be
/// brute-forced and the token need not be rate-limited to stay safe.
const TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub struct InvitationState {
    pub pool: DbPool,
    pub mailer: Option<Arc<Mailer>>,
    /// Base URL the recipient will open, e.g. `https://vault.example.com`.
    pub public_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    /// Policies the redeemed key will carry. Defaults to `["default"]`.
    #[serde(default)]
    pub policies: Option<Vec<String>>,
    #[serde(default)]
    pub expires_in_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateInvitationResponse {
    pub id: Uuid,
    pub email: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// The full link. Returned so an operator can deliver it themselves when
    /// SMTP is not configured, or when they would rather hand it over directly.
    /// This is the only time it is available — only its hash is stored.
    pub invitation_url: String,
    /// Whether the email actually went out. Separate from success: the
    /// invitation exists either way, and an operator must not be left believing
    /// mail was sent when it was not.
    pub email_sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvitationView {
    pub id: Uuid,
    pub email: String,
    pub policies: Vec<String>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: &'static str,
}

impl From<Invitation> for InvitationView {
    fn from(i: Invitation) -> Self {
        let status = if i.used_at.is_some() {
            "accepted"
        } else if i.expires_at <= Utc::now() {
            "expired"
        } else {
            "pending"
        };
        Self {
            id: i.id,
            email: i.email,
            policies: i.policies,
            created_by: i.created_by,
            created_at: i.created_at,
            expires_at: i.expires_at,
            used_at: i.used_at,
            status,
        }
    }
}

/// What the landing page shows before the recipient commits to anything.
///
/// Carries the tenant's display name and nothing else identifying. In
/// particular it does not echo the invited email address: the link may be
/// opened by whoever holds it, and confirming an address to them is a
/// disclosure the recipient never consented to.
#[derive(Debug, Serialize)]
pub struct InvitationPreview {
    pub tenant_name: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether the wizard should walk the recipient through setting up an
    /// authenticator. Guidance, not a statement about the key: the key is
    /// minted usable, and `mfa_store::confirm` is what switches the requirement
    /// on once they finish enrolling.
    pub should_enrol_mfa: bool,
}

#[derive(Debug, Serialize)]
pub struct AcceptResponse {
    /// Shown exactly once. Never recoverable.
    pub api_key: String,
    pub tenant_id: String,
    pub tenant_name: String,
    /// See [`InvitationPreview::should_enrol_mfa`].
    pub should_enrol_mfa: bool,
}

fn err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "code": code, "message": message })),
    )
        .into_response()
}

/// Generate a URL-safe token. Base64url of 32 CSPRNG bytes, unpadded.
fn generate_token() -> Result<String, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};

    let mut raw = [0u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| "CSPRNG failed generating an invitation token".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// A minimal sanity check, not RFC 5322 validation.
///
/// The address is handed to the SMTP layer, which does the real parsing. The
/// point here is to reject obvious mistakes before an invitation row exists for
/// an address that can never receive it.
fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    let mut parts = s.splitn(2, '@');
    match (parts.next(), parts.next()) {
        (Some(local), Some(domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !s.contains(char::is_whitespace)
        }
        _ => false,
    }
}

/// Load a tenant that is present and not soft-deleted.
///
/// `tenant_store::get_tenant` returns soft-deleted tenants too — it selects on
/// id alone. Inviting someone into a deleted organisation would mint a working
/// key against it, so the `deleted_at` check belongs on every path here rather
/// than being remembered at each call site.
async fn load_live_tenant(
    pool: &DbPool,
    tenant_uuid: Uuid,
) -> Result<wslvault_core::types::tenant::Tenant, Response> {
    use wslvault_core::types::tenant::TenantId;

    match wslvault_storage::tenant_store::get_tenant(pool, &TenantId(tenant_uuid)).await {
        Ok(t) if t.deleted_at.is_none() => Ok(t),
        Ok(_) => Err(err(
            StatusCode::NOT_FOUND,
            "tenant_not_found",
            "no such tenant",
        )),
        Err(wslvault_core::VaultError::TenantNotFound { .. }) => Err(err(
            StatusCode::NOT_FOUND,
            "tenant_not_found",
            "no such tenant",
        )),
        Err(e) => {
            error!(error = %e, "tenant lookup failed");
            Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lookup_failed",
                "could not look up the tenant",
            ))
        }
    }
}

/// `POST /v1/tenants/:tenant_id/invitations`
pub async fn create_invitation(
    State(state): State<InvitationState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
    Json(req): Json<CreateInvitationRequest>,
) -> Response {
    let Ok(tenant_uuid) = Uuid::parse_str(tenant_id.trim()) else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_tenant_id",
            "tenant_id must be a UUID",
        );
    };

    if !looks_like_email(&req.email) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_email",
            "a valid email address is required",
        );
    }

    let ttl_hours = req
        .expires_in_hours
        .unwrap_or(DEFAULT_TTL_HOURS)
        .clamp(1, MAX_TTL_HOURS);

    let tenant = match load_live_tenant(&state.pool, tenant_uuid).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let token = match generate_token() {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "token generation failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_generation_failed",
                "could not generate an invitation token",
            );
        }
    };

    let policies = req
        .policies
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| vec!["default".to_string()]);

    let invitation = match invitation_store::create(
        &state.pool,
        tenant_uuid,
        &req.email,
        &token,
        &policies,
        &identity.principal_id,
        Utc::now() + Duration::hours(ttl_hours),
    )
    .await
    {
        Ok(i) => i,
        Err(e) => {
            error!(error = %e, "could not record the invitation");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invitation_not_created",
                "could not create the invitation",
            );
        }
    };

    let url = format!(
        "{}/invite/{}",
        state.public_url.trim_end_matches('/'),
        token
    );

    // Delivery is reported, never assumed. The invitation is already durable at
    // this point, so a mail failure must not roll it back — the operator still
    // holds a usable link.
    let (email_sent, email_error) = match &state.mailer {
        Some(m) => match m
            .send_invitation(&req.email, &tenant.display_name, &url, ttl_hours)
            .await
        {
            Ok(()) => (true, None),
            Err(e) => {
                warn!(error = %e, invitation_id = %invitation.id, "invitation email failed");
                (false, Some(e))
            }
        },
        None => (
            false,
            Some("email is not configured; deliver the link yourself".to_string()),
        ),
    };

    info!(
        invitation_id = %invitation.id,
        tenant_id = %tenant_uuid,
        invited_by = %identity.principal_id,
        email_sent,
        "tenant invitation issued"
    );

    (
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            id: invitation.id,
            email: invitation.email,
            expires_at: invitation.expires_at,
            invitation_url: url,
            email_sent,
            email_error,
        }),
    )
        .into_response()
}

/// `GET /v1/tenants/:tenant_id/invitations`
pub async fn list_invitations(
    State(state): State<InvitationState>,
    // Unused, but kept: extracting it fails the request if `require_admin` is
    // ever detached from this route, so the handler cannot silently become
    // public. Deleting it would remove that tripwire.
    Extension(_identity): Extension<AdminIdentity>,
    Path(tenant_id): Path<String>,
) -> Response {
    let Ok(tenant_uuid) = Uuid::parse_str(tenant_id.trim()) else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_tenant_id",
            "tenant_id must be a UUID",
        );
    };

    match invitation_store::list_for_tenant(&state.pool, tenant_uuid).await {
        Ok(list) => Json(
            list.into_iter()
                .map(InvitationView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            error!(error = %e, "could not list invitations");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "list_failed",
                "could not list invitations",
            )
        }
    }
}

/// `DELETE /v1/tenants/:tenant_id/invitations/:id`
pub async fn revoke_invitation(
    State(state): State<InvitationState>,
    // See the note on list_invitations.
    Extension(_identity): Extension<AdminIdentity>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> Response {
    let (Ok(tenant_uuid), Ok(invitation_id)) = (
        Uuid::parse_str(tenant_id.trim()),
        Uuid::parse_str(id.trim()),
    ) else {
        return err(
            StatusCode::BAD_REQUEST,
            "invalid_id",
            "tenant_id and invitation id must be UUIDs",
        );
    };

    match invitation_store::revoke(&state.pool, invitation_id, tenant_uuid).await {
        // Scoped by tenant in SQL, so a miss is genuinely "not yours or not
        // pending" and says so without confirming the id exists elsewhere.
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no pending invitation with that id",
        ),
        Err(e) => {
            error!(error = %e, "could not revoke the invitation");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "revoke_failed",
                "could not revoke the invitation",
            )
        }
    }
}

/// `GET /v1/invitations/:token` — public. Does not consume the invitation.
pub async fn preview_invitation(
    State(state): State<InvitationState>,
    Path(token): Path<String>,
) -> Response {
    let invitation = match invitation_store::find_by_token(&state.pool, &token).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return err(
                StatusCode::NOT_FOUND,
                "invalid_invitation",
                "this invitation link is not valid",
            )
        }
        Err(e) => {
            error!(error = %e, "invitation preview lookup failed");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lookup_failed",
                "could not check this invitation",
            );
        }
    };

    if !invitation.is_redeemable() {
        // Distinguished so the recipient is told what to do next — ask for a
        // new link, versus "you have already set this up, just sign in".
        let (code, message) = if invitation.used_at.is_some() {
            (
                "invitation_used",
                "this invitation has already been used — sign in with the key you were given",
            )
        } else {
            (
                "invitation_expired",
                "this invitation has expired — ask whoever invited you for a new one",
            )
        };
        return err(StatusCode::GONE, code, message);
    }

    // A missing or deleted tenant falls back to a neutral phrase rather than
    // failing: the invitation itself is still valid, and the recipient cannot
    // act on "tenant lookup failed" anyway.
    let tenant_name = load_live_tenant(&state.pool, invitation.tenant_id)
        .await
        .map(|t| t.display_name)
        .unwrap_or_else(|_| "your organisation".to_string());

    Json(InvitationPreview {
        tenant_name,
        expires_at: invitation.expires_at,
        should_enrol_mfa: true,
    })
    .into_response()
}

/// `POST /v1/invitations/:token/accept` — public. Consumes the invitation.
pub async fn accept_invitation(
    State(state): State<InvitationState>,
    Path(token): Path<String>,
) -> Response {
    // Read first, only to learn the tenant and policies the key must carry. The
    // authoritative single-use check is the UPDATE inside `redeem`; this read
    // decides nothing about whether redemption is allowed.
    let pending = match invitation_store::find_by_token(&state.pool, &token).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return err(
                StatusCode::NOT_FOUND,
                "invalid_invitation",
                "this invitation link is not valid",
            )
        }
        Err(e) => {
            error!(error = %e, "invitation lookup failed during accept");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lookup_failed",
                "could not check this invitation",
            );
        }
    };

    // Reject a spent or expired invitation before minting anything.
    //
    // This is for the error message, not for safety — the authoritative guard
    // is the `WHERE used_at IS NULL AND expires_at > now()` on the redeeming
    // UPDATE, which is what makes concurrent redemptions safe. Without this
    // pre-check the second attempt still fails, but it fails on the duplicate
    // key-name index inside the transaction, and the recipient is told their
    // link is invalid when in fact they already used it — which sends them
    // asking for a new invitation instead of looking for the key they have.
    if !pending.is_redeemable() {
        let (code, message) = if pending.used_at.is_some() {
            (
                "invitation_used",
                "this invitation has already been used — sign in with the key you were given",
            )
        } else {
            (
                "invitation_expired",
                "this invitation has expired — ask whoever invited you for a new one",
            )
        };
        return err(StatusCode::GONE, code, message);
    }

    let tenant = match load_live_tenant(&state.pool, pending.tenant_id).await {
        Ok(t) => t,
        Err(_) => {
            return err(
                StatusCode::GONE,
                "tenant_gone",
                "the organisation this invitation was for no longer exists",
            )
        }
    };

    // Name the key after the invited address, so an operator reading the key
    // list can tell whose it is. Suffixed with the invitation's short id
    // because the active-name index is unique per tenant and the same person
    // may legitimately be invited twice over time.
    let short = pending.id.simple().to_string();
    let key_name = format!(
        "{}-{}",
        pending.email.split('@').next().unwrap_or("invited"),
        &short[..8]
    );

    let (raw_key, row) = ApiKeyManager::mint_row(
        pending.tenant_id,
        &key_name,
        pending.policies.clone(),
        &format!("invitation:{}", pending.id),
        // Invited keys demand an authenticator. The wizard enrols one straight
        // after this call, and `mfa_store::confirm` is what finally switches
        // the requirement on — so the key is usable in the meantime and cannot
        // strand its owner.
        false,
    );

    match invitation_store::redeem(&state.pool, &token, &row).await {
        Ok(invitation) => {
            info!(
                invitation_id = %invitation.id,
                tenant_id = %invitation.tenant_id,
                key_id = %row.id,
                "invitation redeemed; key minted"
            );
            (
                StatusCode::CREATED,
                Json(AcceptResponse {
                    api_key: raw_key,
                    tenant_id: invitation.tenant_id.to_string(),
                    tenant_name: tenant.display_name,
                    should_enrol_mfa: true,
                }),
            )
                .into_response()
        }
        Err(RedeemFailure::AlreadyUsed) => err(
            StatusCode::GONE,
            "invitation_used",
            "this invitation has already been used — sign in with the key you were given",
        ),
        Err(RedeemFailure::Expired) => err(
            StatusCode::GONE,
            "invitation_expired",
            "this invitation has expired — ask whoever invited you for a new one",
        ),
        Err(RedeemFailure::NotFound) => err(
            StatusCode::NOT_FOUND,
            "invalid_invitation",
            "this invitation link is not valid",
        ),
    }
}

/// Routes requiring an administrator. Layered by the caller.
pub fn admin_router(state: InvitationState) -> Router {
    Router::new()
        .route(
            "/v1/tenants/:tenant_id/invitations",
            post(create_invitation),
        )
        .route("/v1/tenants/:tenant_id/invitations", get(list_invitations))
        .route(
            "/v1/tenants/:tenant_id/invitations/:id",
            delete(revoke_invitation),
        )
        .with_state(state)
}

/// Public routes. The recipient has no credential yet; see the module note.
pub fn public_router(state: InvitationState) -> Router {
    Router::new()
        .route("/v1/invitations/:token", get(preview_invitation))
        .route("/v1/invitations/:token/accept", post(accept_invitation))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_url_safe_and_long_enough() {
        let t = generate_token().expect("token");
        // 32 bytes -> 43 base64url chars, unpadded.
        assert_eq!(t.len(), 43);
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "must survive a URL path segment without escaping: {t}"
        );
        assert!(!t.contains('='), "padding would need escaping in a URL");
    }

    #[test]
    fn tokens_do_not_repeat() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn accepts_ordinary_addresses() {
        for good in [
            "a@b.co",
            "first.last@example.com",
            "user+tag@sub.domain.org",
        ] {
            assert!(looks_like_email(good), "should accept {good}");
        }
    }

    #[test]
    fn rejects_addresses_that_can_never_receive() {
        for bad in [
            "",
            "nobody",
            "@example.com",
            "a@b",
            "a@.com",
            "a@b.",
            "a b@c.com",
            "a@b c.com",
        ] {
            assert!(!looks_like_email(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn status_reflects_use_before_expiry() {
        let used = Invitation {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            email: "a@b.test".into(),
            policies: vec![],
            created_by: "op".into(),
            created_at: Utc::now(),
            // Used *and* expired reads as accepted: what happened to it matters
            // more than that the window has since closed.
            expires_at: Utc::now() - Duration::hours(1),
            used_at: Some(Utc::now()),
        };
        assert_eq!(InvitationView::from(used).status, "accepted");
    }
}
