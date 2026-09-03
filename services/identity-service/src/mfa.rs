//! Authenticator-app second factor (TOTP, RFC 6238).
//!
//! Authentication was a single factor: possession of an API key. A key that
//! leaks — in a CI log, a screenshot, a git history — was a complete
//! authentication bypass with nothing standing behind it.
//!
//! # The flow
//!
//! ```text
//! POST /v1/auth/api-key      {api_key}                 → {mfa_required, challenge}
//! POST /v1/auth/mfa/totp     {challenge, code}         → {token, expires_at}
//! ```
//!
//! A key with `mfa_required` gets a short-lived *challenge* instead of a token.
//! The challenge is worthless on its own: it names a pending login and expires
//! in two minutes. Only a valid code turns it into a token.
//!
//! Machine keys — the External Secrets Operator, CI, the SDKs — keep the
//! one-step exchange, because a service account cannot read an authenticator
//! app and forcing it would break every non-interactive integration. The
//! exemption is per key, not a global switch somebody can forget they left off.
//!
//! # Enrolment
//!
//! ```text
//! POST /v1/auth/mfa/totp/enroll   → {secret, otpauth_uri, recovery_codes}
//! POST /v1/auth/mfa/totp/confirm  {code} → enrolment becomes active
//! ```
//!
//! Two-phase on purpose. A secret that is issued but never confirmed can
//! neither satisfy a challenge nor lock anyone out, so a half-finished
//! enrolment — the browser closed on the QR screen — is harmless.
//!
//! # Replay
//!
//! A TOTP code is valid for a whole 30-second step, so without a defence an
//! attacker who observes one — over the shoulder, through a phishing proxy —
//! can reuse it for the rest of that window. `last_used_step` records the
//! highest step already accepted, which makes each code single-use.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

/// How long a pending MFA challenge stays usable.
///
/// Long enough to open an authenticator and read a code; short enough that a
/// challenge captured from a log is worthless by the time anyone finds it.
const CHALLENGE_TTL_SECONDS: i64 = 120;

/// Steps of clock skew tolerated either side of now.
///
/// One step (30s) each way. Phones drift; going wider would widen the replay
/// window that `last_used_step` exists to close.
const TOTP_SKEW: u8 = 1;

/// Standard TOTP parameters. Matches what every authenticator app assumes, so
/// a QR code scans without the user configuring anything.
const TOTP_DIGITS: usize = 6;
const TOTP_STEP_SECONDS: u64 = 30;

/// A login that has passed the key check and is waiting on a code.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub api_key_id: Uuid,
    pub tenant_id: String,
    pub policies: Vec<String>,
    pub superuser: bool,
    pub expires_at: i64,
}

/// In-flight MFA challenges.
///
/// Deliberately in-process and short-lived: a challenge is not a credential and
/// nothing is lost by dropping it on restart — the user simply logs in again.
/// Persisting it would create a second thing to keep secret for no gain.
///
/// ponytail: in-process means a challenge must return to the same replica.
/// Fine behind a session-affine or single-replica identity-service; move to
/// Redis or Postgres if that stops being true.
#[derive(Clone, Default)]
pub struct ChallengeStore {
    inner: Arc<RwLock<HashMap<String, PendingChallenge>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a challenge id for a login awaiting its second factor.
    pub async fn issue(&self, pending: PendingChallenge) -> String {
        let id = Uuid::now_v7().to_string();
        let mut guard = self.inner.write().await;
        // Opportunistically drop anything expired, so a login burst does not
        // leave the map growing forever.
        let now = chrono::Utc::now().timestamp();
        guard.retain(|_, c| c.expires_at > now);
        guard.insert(id.clone(), pending);
        id
    }

    /// Consume a challenge. Removing it on read makes it single-use, so a
    /// captured challenge cannot be replayed even within its TTL.
    pub async fn take(&self, id: &str) -> Option<PendingChallenge> {
        let mut guard = self.inner.write().await;
        let pending = guard.remove(id)?;
        if pending.expires_at <= chrono::Utc::now().timestamp() {
            return None;
        }
        Some(pending)
    }
}

/// Generate a fresh 20-byte TOTP secret, base32-encoded as authenticator apps
/// expect.
pub fn generate_secret() -> Result<String, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut raw = [0u8; 20];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| "CSPRNG failed generating a TOTP secret".to_string())?;
    Ok(base32_encode(&raw))
}

/// RFC 4648 base32 without padding — the encoding `otpauth://` URIs use.
///
/// Hand-rolled because it is a fixed alphabet lookup, not cryptography, and it
/// avoids a dependency for thirty lines.
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for c in s.trim().to_ascii_uppercase().bytes() {
        if c == b'=' {
            continue;
        }
        let idx = ALPHABET.iter().position(|&a| a == c)? as u16;
        buffer = (buffer << 5) | idx;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// Build the `otpauth://` URI an authenticator app scans.
pub fn otpauth_uri(secret_b32: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}\
         &algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )
}

/// The TOTP step a Unix timestamp falls in. This is what replay protection
/// compares against.
pub fn step_at(unix_seconds: i64) -> i64 {
    unix_seconds / TOTP_STEP_SECONDS as i64
}

/// Check `code` against `secret_b32`, tolerating [`TOTP_SKEW`] steps of drift.
///
/// Returns the step the code belonged to, so the caller can record it and
/// refuse the same code a second time. `None` means no accepted step matched.
///
/// Comparison is constant-time: a code is a six-digit secret, and comparing it
/// with `==` would leak its prefix through timing to anyone able to measure.
pub fn verify_code(secret_b32: &str, code: &str, now: i64) -> Option<i64> {
    use subtle::ConstantTimeEq;

    let secret = base32_decode(secret_b32)?;
    let current = step_at(now);

    for offset in -(TOTP_SKEW as i64)..=(TOTP_SKEW as i64) {
        let step = current + offset;
        let expected = hotp(&secret, step as u64);
        if bool::from(expected.as_bytes().ct_eq(code.trim().as_bytes())) {
            return Some(step);
        }
    }
    None
}

/// HOTP (RFC 4226) at a given counter — the primitive TOTP is built on.
fn hotp(secret: &[u8], counter: u64) -> String {
    use ring::hmac;

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let digest = tag.as_ref();

    // Dynamic truncation, RFC 4226 §5.4.
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    let binary = ((digest[offset] & 0x7F) as u32) << 24
        | (digest[offset + 1] as u32) << 16
        | (digest[offset + 2] as u32) << 8
        | (digest[offset + 3] as u32);

    let modulus = 10u32.pow(TOTP_DIGITS as u32);
    format!("{:0width$}", binary % modulus, width = TOTP_DIGITS)
}

/// Generate single-use recovery codes and their hashes.
///
/// Without these, losing a phone means losing the account — and in a vault that
/// means losing access to every secret the key could read.
pub fn generate_recovery_codes(count: usize) -> Result<Vec<(String, String)>, String> {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut raw = [0u8; 10];
        rng.fill(&mut raw)
            .map_err(|_| "CSPRNG failed generating a recovery code".to_string())?;
        // Grouped for legibility: these get written down.
        let encoded = base32_encode(&raw);
        let code = format!("{}-{}", &encoded[..8], &encoded[8..16]);
        // Hashed through the same function that verifies, so the two can never
        // disagree about normalisation.
        let hash = hash_recovery_code(&code);
        out.push((code, hash));
    }
    Ok(out)
}

/// SHA-256 of a recovery code, hex. Only the hash is ever stored.
///
/// Trims and upper-cases first. These codes are written on paper and typed back
/// months later, often on a phone that lower-cases or auto-capitalises without
/// being asked — and the generated alphabet (RFC 4648 base32) is upper-case
/// only, so folding case cannot make two distinct codes collide. Without this,
/// a correctly-transcribed code is rejected on the strength of its case, at the
/// exact moment the user has already lost their phone.
pub fn hash_recovery_code(code: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(code.trim().to_ascii_uppercase().as_bytes()))
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// Always true. Present so a client can branch without inspecting status.
    pub mfa_required: bool,
    /// Opaque id to return with the code.
    pub challenge: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub challenge: String,
    /// Six-digit authenticator code, or a recovery code.
    pub code: String,
}

pub fn challenge_response(challenge: String) -> Response {
    (
        StatusCode::OK,
        Json(ChallengeResponse {
            mfa_required: true,
            challenge,
            expires_in_seconds: CHALLENGE_TTL_SECONDS,
        }),
    )
        .into_response()
}

pub fn challenge_expiry() -> i64 {
    chrono::Utc::now().timestamp() + CHALLENGE_TTL_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test from RFC 4226 Appendix D, so the HOTP core is checked
    /// against the specification rather than against itself.
    #[test]
    fn hotp_matches_rfc4226_test_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(&hotp(secret, counter as u64), want, "counter {counter}");
        }
    }

    #[test]
    fn base32_round_trips() {
        let data = b"12345678901234567890";
        let encoded = base32_encode(data);
        assert_eq!(base32_decode(&encoded).as_deref(), Some(&data[..]));
        // Authenticator apps only accept the RFC 4648 alphabet.
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn a_current_code_verifies() {
        let secret = base32_encode(b"12345678901234567890");
        let now = chrono::Utc::now().timestamp();
        let code = hotp(b"12345678901234567890", step_at(now) as u64);
        assert_eq!(verify_code(&secret, &code, now), Some(step_at(now)));
    }

    /// Phones drift, so one step either side is accepted — and no more, because
    /// every extra step widens the window a stolen code stays usable in.
    #[test]
    fn adjacent_steps_are_accepted_but_distant_ones_are_not() {
        let raw = b"12345678901234567890";
        let secret = base32_encode(raw);
        let now = chrono::Utc::now().timestamp();
        let step = step_at(now);

        for offset in [-1i64, 0, 1] {
            let code = hotp(raw, (step + offset) as u64);
            assert_eq!(
                verify_code(&secret, &code, now),
                Some(step + offset),
                "offset {offset} should verify"
            );
        }
        for offset in [-2i64, 2, 10] {
            let code = hotp(raw, (step + offset) as u64);
            assert_eq!(
                verify_code(&secret, &code, now),
                None,
                "offset {offset} is outside the skew window"
            );
        }
    }

    #[test]
    fn a_wrong_code_is_rejected() {
        let secret = base32_encode(b"12345678901234567890");
        let now = chrono::Utc::now().timestamp();
        assert_eq!(verify_code(&secret, "000000", now), None);
        assert_eq!(verify_code(&secret, "", now), None);
        assert_eq!(verify_code(&secret, "not-a-code", now), None);
    }

    /// A code from another enrolment must not open this one.
    #[test]
    fn a_code_from_a_different_secret_is_rejected() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        let now = chrono::Utc::now().timestamp();
        let code_for_b = hotp(&base32_decode(&b).unwrap(), step_at(now) as u64);
        assert_eq!(verify_code(&a, &code_for_b, now), None);
    }

    #[test]
    fn generated_secrets_are_distinct_and_scannable() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_ne!(a, b);
        assert_eq!(base32_decode(&a).map(|v| v.len()), Some(20));
        assert!(otpauth_uri(&a, "user@example.com", "WSLVault").starts_with("otpauth://totp/"));
    }

    /// Pins the `otpauth://` parameters that authenticator apps actually read.
    ///
    /// Authy is the reason this is asserted rather than assumed. Google
    /// Authenticator ignores `algorithm`, `digits` and `period` and just assumes
    /// SHA1/6/30, so a drift away from those defaults still works there and
    /// silently produces codes Authy rejects — the failure shows up as "the app
    /// gives the wrong code", with nothing wrong in any log.
    ///
    /// Also pins the `Issuer:Account` label prefix alongside the `issuer=`
    /// parameter. Authy uses it to name and group the entry; without it every
    /// key lands as an unlabelled account.
    #[test]
    fn otpauth_uri_is_what_authenticator_apps_expect() {
        let secret = generate_secret().unwrap();
        let uri = otpauth_uri(&secret, "3f2a1b4c-0000-0000-0000-000000000001", "WSLVault");

        // The label carries the issuer prefix, and the issuer is repeated as a
        // parameter. Both are required for correct display in Authy.
        assert!(
            uri.starts_with("otpauth://totp/WSLVault:3f2a1b4c-0000-0000-0000-000000000001?"),
            "label must be Issuer:Account — got {uri}"
        );
        assert!(
            uri.contains("&issuer=WSLVault"),
            "issuer parameter missing: {uri}"
        );

        // SHA1/6/30 is the only combination every TOTP app agrees on. Changing
        // any of these is a breaking change for already-enrolled authenticators,
        // not a tuning knob.
        assert!(
            uri.contains("&algorithm=SHA1"),
            "algorithm must be SHA1: {uri}"
        );
        assert!(uri.contains("&digits=6"), "digits must be 6: {uri}");
        assert!(uri.contains("&period=30"), "period must be 30: {uri}");

        // The secret must be base32 with no padding: `=` is not valid in the
        // query string unescaped, and Authy will not import a padded secret.
        assert!(
            uri.contains(&format!("secret={secret}")),
            "secret not in the URI: {uri}"
        );
        assert!(
            !secret.contains('='),
            "base32 secret must be unpadded: {secret}"
        );
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
            "secret must be RFC 4648 base32 alphabet: {secret}"
        );
    }

    #[test]
    fn recovery_codes_are_distinct_and_only_hashes_are_storable() {
        let codes = generate_recovery_codes(8).unwrap();
        assert_eq!(codes.len(), 8);

        let plain: Vec<&String> = codes.iter().map(|(c, _)| c).collect();
        let mut deduped = plain.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 8, "recovery codes must not repeat");

        for (code, hash) in &codes {
            assert_eq!(&hash_recovery_code(code), hash);
            assert!(
                !hash.contains(code),
                "the stored hash must not embed the code"
            );
            assert_eq!(hash.len(), 64);
        }
    }

    // ── Challenges ───────────────────────────────────────────────────────────

    fn pending() -> PendingChallenge {
        PendingChallenge {
            api_key_id: Uuid::now_v7(),
            tenant_id: "t".into(),
            policies: vec![],
            superuser: false,
            expires_at: challenge_expiry(),
        }
    }

    /// Single-use: a captured challenge must not be replayable even inside its
    /// TTL, or observing one login would grant a second.
    #[tokio::test]
    async fn a_challenge_can_only_be_taken_once() {
        let store = ChallengeStore::new();
        let id = store.issue(pending()).await;
        assert!(store.take(&id).await.is_some());
        assert!(store.take(&id).await.is_none());
    }

    #[tokio::test]
    async fn an_expired_challenge_is_refused() {
        let store = ChallengeStore::new();
        let mut p = pending();
        p.expires_at = chrono::Utc::now().timestamp() - 1;
        let id = store.issue(p).await;
        assert!(store.take(&id).await.is_none());
    }

    #[tokio::test]
    async fn an_unknown_challenge_is_refused() {
        let store = ChallengeStore::new();
        assert!(store.take("no-such-challenge").await.is_none());
    }
}
