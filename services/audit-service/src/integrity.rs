//! HMAC-SHA256 integrity signing and verification for audit records.
//!
//! Every audit record is signed before storage so that any off-line tampering
//! (e.g. direct manipulation of a dump) is detectable. The signing key should
//! be a per-tenant secret loaded from the secrets manager; for the in-process
//! implementation here a static environment-provided key is used.
//!
//! The canonical message covers the record's own integrity-protected fields —
//! id, tenant_id, principal_id, action, resource, outcome, outcome_detail,
//! client_ip, timestamp, details — AND its position in the tenant's hash
//! chain: `seq` and `prev_hash`.
//!
//! Including the chain is what makes the log tamper-EVIDENT rather than merely
//! signed. Signing each record in isolation detects an edit to a row and
//! nothing else: deleting a record, truncating the log, or reordering it all
//! leave the survivors verifying perfectly. Because each signature commits to
//! its predecessor's signature, every record transitively commits to the whole
//! history before it, and removing any of them breaks verification from that
//! point onward.

use ring::hmac;

use crate::store::AuditRecord;

/// Per-tenant HMAC signing keys, derived from one master secret.
///
/// The doc comment on this module always claimed per-tenant keys; the code
/// used a single global one, with a hardcoded fallback
/// (`b"wslvault-audit-default-hmac-key-256bits!!"`) committed to this
/// repository. Anyone with the source could forge audit records for any
/// deployment that had not set `AUDIT_SIGNING_KEY`, and one leaked key
/// compromised every tenant's log at once.
///
/// Keys are now derived with HKDF-SHA256 from the master, with the tenant id
/// as context, so compromising one tenant's derived key does not yield the
/// master or any other tenant's key.
#[derive(Clone)]
pub struct AuditSigner {
    master: Vec<u8>,
}

impl AuditSigner {
    /// Build a signer from `AUDIT_SIGNING_KEY`.
    ///
    /// Returns an error when it is unset or too short. There is deliberately no
    /// fallback: a well-known default is worse than refusing to start, because
    /// it produces a log that looks signed and is not.
    pub fn from_env() -> Result<Self, String> {
        const MIN_LEN: usize = 32;
        let key = std::env::var("AUDIT_SIGNING_KEY").map_err(|_| {
            "AUDIT_SIGNING_KEY is required: audit records cannot be signed without it".to_string()
        })?;
        if key.len() < MIN_LEN {
            return Err(format!(
                "AUDIT_SIGNING_KEY must be at least {MIN_LEN} bytes, got {}",
                key.len()
            ));
        }
        Ok(Self::from_key(key.as_bytes()))
    }

    /// Construct directly from key material. Test and embedding use.
    pub fn from_key(master: &[u8]) -> Self {
        Self {
            master: master.to_vec(),
        }
    }

    /// The signing key for one tenant.
    pub fn key_for(&self, tenant_id: &str) -> Vec<u8> {
        let info = format!("wslvault:audit:v1:{tenant_id}");
        match wslvault_core::crypto::kdf::derive_key(&self.master, None, info.as_bytes()) {
            Ok(k) => k.to_vec(),
            // HKDF-SHA256 cannot fail for a 32-byte output; if it somehow did,
            // falling back to the master would silently collapse every tenant
            // onto one key, so panic instead.
            Err(e) => unreachable!("HKDF failed for a 32-byte output: {e}"),
        }
    }
}

/// Compute an HMAC-SHA256 signature over the integrity-protected fields of
/// `record`, using `key` as the signing material.  Returns a hex-encoded string.
pub fn sign_event(record: &AuditRecord, key: &[u8]) -> String {
    sign_event_chained(record, key, record.seq, &record.prev_hash)
}

/// Sign a record at an explicit chain position.
///
/// Used on the append path, where the position is assigned by the storage
/// layer inside the same transaction that writes the row.
pub fn sign_event_chained(record: &AuditRecord, key: &[u8], seq: i64, prev_hash: &str) -> String {
    let message = build_canonical_message_chained(record, seq, prev_hash);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, message.as_bytes());
    hex::encode(tag.as_ref())
}

/// Verify that `signature` matches the HMAC-SHA256 of `record` under `key`.
///
/// Uses `ring::hmac::verify`, a constant-time comparison, so a caller cannot
/// learn the expected MAC by timing repeated attempts.
///
/// This was `#[cfg(test)]`, which meant it did not exist in a release build and
/// `query_events` returned records unchecked. A signature nobody verifies is
/// decoration.
pub fn verify_signature(record: &AuditRecord, key: &[u8], signature: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };

    let message = build_canonical_message(record);
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&verification_key, message.as_bytes(), &sig_bytes).is_ok()
}

/// Produce the deterministic string that is fed into HMAC-SHA256.
///
/// All fields are concatenated with a null-byte delimiter so that adjacent
/// fields cannot be made to collide (e.g. action="a\x00b" + resource="c"
/// cannot equal action="a" + resource="b\x00c").
fn build_canonical_message(record: &AuditRecord) -> String {
    build_canonical_message_chained(record, record.seq, &record.prev_hash)
}

fn build_canonical_message_chained(record: &AuditRecord, seq: i64, prev_hash: &str) -> String {
    let details_compact = record.details.to_string();
    format!(
        "{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}",
        record.id,
        record.tenant_id,
        record.principal_id,
        record.action,
        record.resource,
        record.outcome,
        record.outcome_detail,
        record.client_ip,
        record.timestamp.to_rfc3339(),
        details_compact,
        seq,
        prev_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AuditRecord;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_record() -> AuditRecord {
        AuditRecord {
            id: Uuid::now_v7(),
            tenant_id: "tenant-1".into(),
            principal_id: "user-abc".into(),
            action: "secret.read".into(),
            resource: "/prod/db/password".into(),
            outcome: "success".into(),
            outcome_detail: "".into(),
            details: serde_json::json!({"env": "prod"}),
            client_ip: "10.0.0.1".into(),
            signature: String::new(), // populated after signing
            timestamp: Utc::now(),
            seq: 1,
            prev_hash: String::new(),
            verified: None,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = b"super-secret-signing-key-32bytes";
        let record = sample_record();
        let sig = sign_event(&record, key);
        assert!(verify_signature(&record, key, &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = b"super-secret-signing-key-32bytes";
        let wrong_key = b"a-completely-different-key-32xxx";
        let record = sample_record();
        let sig = sign_event(&record, key);
        assert!(!verify_signature(&record, wrong_key, &sig));
    }

    #[test]
    fn tampered_field_fails_verification() {
        let key = b"super-secret-signing-key-32bytes";
        let record = sample_record();
        let sig = sign_event(&record, key);

        // Modify the action to simulate tampering.
        let mut tampered = record;
        tampered.action = "secret.delete".into();

        assert!(!verify_signature(&tampered, key, &sig));
    }

    // ── The chain is what makes deletion detectable ──────────────────────────

    #[test]
    fn signature_covers_the_chain_position() {
        let key = b"super-secret-signing-key-32bytes";
        let record = sample_record();

        let at_1 = sign_event_chained(&record, key, 1, "");
        let at_2 = sign_event_chained(&record, key, 2, "");
        assert_ne!(
            at_1, at_2,
            "the same record at a different position must sign differently, \
             or reordering would be undetectable"
        );
    }

    #[test]
    fn signature_covers_the_predecessor() {
        let key = b"super-secret-signing-key-32bytes";
        let record = sample_record();

        let after_a = sign_event_chained(&record, key, 2, "aaaa");
        let after_b = sign_event_chained(&record, key, 2, "bbbb");
        assert_ne!(
            after_a, after_b,
            "a record must commit to its predecessor, or deleting one would \
             leave the survivors verifying"
        );
    }

    /// Removing a record from the middle of a chain must break verification of
    /// the record that followed it — that is the whole point of chaining.
    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let key = b"super-secret-signing-key-32bytes";

        let mut first = sample_record();
        first.seq = 1;
        first.prev_hash = String::new();
        first.signature = sign_event(&first, key);

        let mut second = sample_record();
        second.seq = 2;
        second.prev_hash = first.signature.clone();
        second.signature = sign_event(&second, key);

        let mut third = sample_record();
        third.seq = 3;
        third.prev_hash = second.signature.clone();
        third.signature = sign_event(&third, key);

        // Intact: all three verify.
        for r in [&first, &second, &third] {
            assert!(verify_signature(r, key, &r.signature));
        }

        // Excise `second` and re-point `third` at `first`, as an attacker
        // covering their tracks would have to. Its signature no longer matches.
        let mut rewritten = third.clone();
        rewritten.prev_hash = first.signature.clone();
        rewritten.seq = 2;
        assert!(
            !verify_signature(&rewritten, key, &third.signature),
            "a record moved to hide a deletion must fail verification"
        );
    }

    // ── Per-tenant key derivation ────────────────────────────────────────────

    #[test]
    fn each_tenant_gets_a_distinct_key() {
        let signer = AuditSigner::from_key(b"master-secret-at-least-32-bytes!!");
        let a = signer.key_for("tenant-a");
        let b = signer.key_for("tenant-b");
        assert_ne!(a, b, "one leaked key must not compromise every tenant");
        assert_eq!(a, signer.key_for("tenant-a"), "derivation is deterministic");
        assert_ne!(a, b"master-secret-at-least-32-bytes!!".to_vec());
    }

    #[test]
    fn a_record_signed_for_one_tenant_does_not_verify_under_another() {
        let signer = AuditSigner::from_key(b"master-secret-at-least-32-bytes!!");
        let record = sample_record();
        let sig = sign_event(&record, &signer.key_for("tenant-1"));
        assert!(verify_signature(&record, &signer.key_for("tenant-1"), &sig));
        assert!(!verify_signature(
            &record,
            &signer.key_for("tenant-2"),
            &sig
        ));
    }
}
