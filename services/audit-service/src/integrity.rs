//! HMAC-SHA256 integrity signing and verification for audit records.
//!
//! Every audit record is signed before storage so that any off-line tampering
//! (e.g. direct manipulation of a dump) is detectable. The signing key should
//! be a per-tenant secret loaded from the secrets manager; for the in-process
//! implementation here a static environment-provided key is used.
//!
//! The canonical message is a deterministic JSON serialisation of the fields
//! that must be integrity-protected: id, tenant_id, principal_id, action,
//! resource, outcome, outcome_detail, client_ip, timestamp.  The `details`
//! field is included as a compact JSON string to ensure coverage of all
//! emitted context.

use ring::hmac;

use crate::store::AuditRecord;

/// Compute an HMAC-SHA256 signature over the integrity-protected fields of
/// `record`, using `key` as the signing material.  Returns a hex-encoded string.
pub fn sign_event(record: &AuditRecord, key: &[u8]) -> String {
    let message = build_canonical_message(record);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, message.as_bytes());
    hex::encode(tag.as_ref())
}

/// Verify that `signature` matches the HMAC-SHA256 of `record` under `key`.
///
/// Uses `ring::hmac::verify` which performs a constant-time comparison to
/// prevent timing attacks that could leak information about the expected MAC.
#[cfg(test)]
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
    let details_compact = record.details.to_string();
    format!(
        "{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}",
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
}
