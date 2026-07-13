//! CA and certificate issuance operations using the `rcgen` crate.
//!
//! All functions in this module are synchronous (rcgen is sync) and should be
//! called via `tokio::task::spawn_blocking` when invoked from async handlers.
//!
//! # Certificate serial numbers
//!
//! Serials are generated as random 64-bit integers (printed as lowercase hex)
//! to avoid predictable sequences while staying well within the 20-byte X.509
//! limit.  Each call to `generate_serial` is independent.

use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::PkiError;
use crate::types::{KeyType, KeyUsage, PkiRole};

// ---------------------------------------------------------------------------
// Serial generation
// ---------------------------------------------------------------------------

/// Generate a random 64-bit serial number as lowercase hex.
///
/// Cryptographically random via `ring::rand::SystemRandom`.
pub fn generate_serial() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes).expect("OS RNG must be available");
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// rcgen algorithm helper
// ---------------------------------------------------------------------------

/// Map our `KeyType` enum to an rcgen `KeyPair`.
///
/// The `KeyPair` owns the private key material; callers who need to persist
/// the private key should call `key_pair.serialize_pem()` immediately and
/// store the result in a `Zeroizing<String>`.
///
/// # RSA support
///
/// RSA key generation via rcgen 0.13 requires the `aws_lc_rs` backend.
/// The default `ring` backend supports ECDSA P-256 only.  Attempting RSA
/// generation with the `ring` backend returns `PkiError::CertGenerationFailed`
/// with a clear message.  Production deployments that require RSA certificates
/// should compile with `rcgen/aws_lc_rs`.
fn generate_key_pair(key_type: &KeyType) -> Result<KeyPair, PkiError> {
    let alg = match key_type {
        KeyType::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        KeyType::Rsa2048 | KeyType::Rsa4096 => &rcgen::PKCS_RSA_SHA256,
    };

    KeyPair::generate_for(alg).map_err(|e| PkiError::CertGenerationFailed {
        reason: format!("key generation failed for {key_type}: {e}"),
    })
}

// ---------------------------------------------------------------------------
// CA generation
// ---------------------------------------------------------------------------

/// Output of a CA generation operation.
pub struct CaOutput {
    /// PEM-encoded self-signed CA certificate.
    pub cert_pem: String,
    /// PEM-encoded CA private key (caller must zeroize after persisting).
    pub key_pem: Zeroizing<String>,
    /// Serial number of the CA certificate (hex).
    pub serial: String,
}

/// Generate a self-signed root CA certificate for a tenant.
///
/// # Parameters
///
/// - `common_name` — Subject CN of the CA, e.g. `"Example Root CA"`.
/// - `ttl_seconds` — Validity period in seconds from now.
/// - `key_type` — Asymmetric key algorithm.
///
/// Returns `CaOutput` on success.
pub fn generate_ca(
    common_name: &str,
    ttl_seconds: i64,
    key_type: &KeyType,
) -> Result<CaOutput, PkiError> {
    let key_pair = generate_key_pair(key_type)?;

    let serial = generate_serial();
    let serial_bytes = hex::decode(&serial).expect("generate_serial returns valid hex");

    let not_before = Utc::now();
    let not_after = not_before + Duration::seconds(ttl_seconds);

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = rcgen_time(not_before);
    params.not_after = rcgen_time(not_after);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    // CA certificates should have the keyCertSign and cRLSign key usages set.
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| PkiError::CertGenerationFailed {
            reason: format!("CA self-sign failed: {e}"),
        })?;

    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    Ok(CaOutput {
        cert_pem,
        key_pem,
        serial,
    })
}

// ---------------------------------------------------------------------------
// Leaf certificate issuance
// ---------------------------------------------------------------------------

/// Output of a leaf certificate issuance.
pub struct IssueOutput {
    /// PEM-encoded leaf certificate.
    pub cert_pem: String,
    /// PEM-encoded leaf private key (caller must zeroize after returning to client).
    pub private_key_pem: Zeroizing<String>,
    /// The CA cert PEM (single-element chain for a one-level hierarchy).
    pub ca_chain_pem: String,
    /// Hex serial of the issued certificate.
    pub serial: String,
    /// UTC expiry time.
    pub not_after: DateTime<Utc>,
}

/// Issue a leaf certificate signed by the tenant CA.
///
/// # Parameters
///
/// - `ca_cert_pem` — PEM of the tenant CA certificate.
/// - `ca_key_pem` — PEM of the tenant CA private key (must be `Zeroizing` so
///   it is wiped after this call).
/// - `role` — Validated role record used to enforce constraints.
/// - `common_name` — Subject CN requested by the caller.
/// - `san_dns_names` — Additional DNS SAN entries.
/// - `san_ip_addrs` — IP address SAN entries (only allowed when `role.allow_ip_sans`).
/// - `ttl_seconds` — Desired lifetime; capped to `role.max_ttl_seconds`.
///
/// # Constraint enforcement
///
/// - `common_name` and each DNS SAN must match `role.allowed_domains` per the
///   `allowed_domains_match` helper below.
/// - IP SANs are rejected when `role.allow_ip_sans` is false.
/// - `ttl_seconds` is silently capped to `role.max_ttl_seconds`; a value of 0
///   or negative falls back to `role.max_ttl_seconds`.
pub fn issue_leaf(
    ca_cert_pem: &str,
    ca_key_pem: &Zeroizing<String>,
    role: &PkiRole,
    common_name: &str,
    san_dns_names: &[String],
    san_ip_addrs: &[std::net::IpAddr],
    ttl_seconds: i64,
) -> Result<IssueOutput, PkiError> {
    // ---- Enforce role constraints -------------------------------------------

    // Validate common_name against role domains.
    check_domain_allowed(role, common_name)?;

    // Validate additional DNS SANs.
    for dns_name in san_dns_names {
        check_domain_allowed(role, dns_name)?;
    }

    // Reject IP SANs when the role does not permit them.
    if !san_ip_addrs.is_empty() && !role.allow_ip_sans {
        return Err(PkiError::RoleConstraintViolated {
            reason: "role does not allow IP SANs".into(),
        });
    }

    // Cap TTL to role maximum.
    let effective_ttl = if ttl_seconds > 0 && ttl_seconds < role.max_ttl_seconds {
        ttl_seconds
    } else {
        role.max_ttl_seconds
    };

    // ---- Build leaf certificate params -------------------------------------

    let leaf_key = generate_key_pair(&role.key_type)?;

    let serial = generate_serial();
    let serial_bytes = hex::decode(&serial).expect("generate_serial returns valid hex");

    let not_before = Utc::now();
    let not_after = not_before + Duration::seconds(effective_ttl);

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.not_before = rcgen_time(not_before);
    params.not_after = rcgen_time(not_after);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    // Collect SAN entries.
    let mut subject_alt_names: Vec<SanType> = Vec::new();

    // Always add CN as a DNS SAN for consistency.
    subject_alt_names.push(SanType::DnsName(common_name.try_into().map_err(|_| {
        PkiError::CertGenerationFailed {
            reason: format!("invalid DNS name: {common_name}"),
        }
    })?));

    for dns_name in san_dns_names {
        subject_alt_names.push(SanType::DnsName(dns_name.as_str().try_into().map_err(
            |_| PkiError::CertGenerationFailed {
                reason: format!("invalid DNS SAN: {dns_name}"),
            },
        )?));
    }

    for ip in san_ip_addrs {
        subject_alt_names.push(SanType::IpAddress(*ip));
    }

    params.subject_alt_names = subject_alt_names;

    // Map role key usages to rcgen extended key usage purposes.
    params.extended_key_usages = role
        .key_usages
        .iter()
        .filter_map(|ku| match ku {
            KeyUsage::ServerAuth => Some(ExtendedKeyUsagePurpose::ServerAuth),
            KeyUsage::ClientAuth => Some(ExtendedKeyUsagePurpose::ClientAuth),
            KeyUsage::CodeSigning => Some(ExtendedKeyUsagePurpose::CodeSigning),
            KeyUsage::EmailProtection => Some(ExtendedKeyUsagePurpose::EmailProtection),
            KeyUsage::TimeStamping => Some(ExtendedKeyUsagePurpose::TimeStamping),
            KeyUsage::OcspSigning => Some(ExtendedKeyUsagePurpose::OcspSigning),
        })
        .collect();

    // ---- Sign with CA key ---------------------------------------------------

    // Parse the CA key material from the PEM so rcgen can sign the leaf.
    let ca_key_pair =
        KeyPair::from_pem(ca_key_pem).map_err(|e| PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA private key: {e}"),
        })?;

    // Parse the CA certificate parameters so we can use it as the issuer.
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem).map_err(|e| {
        PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA cert: {e}"),
        }
    })?;

    let ca_cert =
        ca_params
            .self_signed(&ca_key_pair)
            .map_err(|e| PkiError::CertGenerationFailed {
                reason: format!("failed to reconstruct CA cert for signing: {e}"),
            })?;

    let leaf_cert = params
        .signed_by(&leaf_key, &ca_cert, &ca_key_pair)
        .map_err(|e| PkiError::CertGenerationFailed {
            reason: format!("leaf certificate signing failed: {e}"),
        })?;

    let cert_pem = leaf_cert.pem();
    let private_key_pem = Zeroizing::new(leaf_key.serialize_pem());

    Ok(IssueOutput {
        cert_pem,
        private_key_pem,
        ca_chain_pem: ca_cert_pem.to_string(),
        serial,
        not_after,
    })
}

// ---------------------------------------------------------------------------
// CSR signing
// ---------------------------------------------------------------------------

/// Output of a CSR-signing operation.
pub struct SignCsrOutput {
    /// PEM-encoded signed certificate.
    pub cert_pem: String,
    /// The CA cert PEM (chain).
    pub ca_chain_pem: String,
    /// Hex serial of the signed certificate.
    pub serial: String,
    /// UTC expiry time.
    pub not_after: DateTime<Utc>,
}

/// Sign a PEM-encoded CSR with the tenant CA, enforcing role constraints on
/// the CSR's Subject CN and any SANs carried in the CSR extensions.
///
/// # Security note
///
/// Validation is performed on the parsed CSR fields, not on the raw bytes, so
/// callers must pass the output of `x509-parser`'s PEM → DER → parse pipeline
/// rather than trusting raw strings from the request body.
pub fn sign_csr(
    ca_cert_pem: &str,
    ca_key_pem: &Zeroizing<String>,
    role: &PkiRole,
    csr_pem: &str,
    ttl_seconds: i64,
) -> Result<SignCsrOutput, PkiError> {
    // Parse and validate the CSR using x509-parser to extract CN and SANs.
    let csr_info = parse_and_validate_csr(role, csr_pem)?;

    // Cap TTL.
    let effective_ttl = if ttl_seconds > 0 && ttl_seconds < role.max_ttl_seconds {
        ttl_seconds
    } else {
        role.max_ttl_seconds
    };

    let serial = generate_serial();
    let serial_bytes = hex::decode(&serial).expect("generate_serial returns valid hex");

    let not_before = Utc::now();
    let not_after = not_before + Duration::seconds(effective_ttl);

    // Parse the CSR with rcgen.
    let mut csr =
        CertificateSigningRequestParams::from_pem(csr_pem).map_err(|e| PkiError::InvalidCsr {
            reason: format!("rcgen failed to parse CSR: {e}"),
        })?;

    // Override validity window and serial from the CSR's embedded params, since
    // the CSR itself does not carry these — we impose them from the role + request.
    csr.params.is_ca = IsCa::NoCa;
    csr.params.not_before = rcgen_time(not_before);
    csr.params.not_after = rcgen_time(not_after);
    csr.params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    // Enforce IP SAN policy on the SANs already parsed from the CSR.
    let has_ip_san = csr
        .params
        .subject_alt_names
        .iter()
        .any(|s| matches!(s, SanType::IpAddress(_)));

    if has_ip_san && !role.allow_ip_sans {
        return Err(PkiError::RoleConstraintViolated {
            reason: "role does not allow IP SANs".into(),
        });
    }

    // Validate CN from the parsed info (already checked in parse_and_validate_csr,
    // but re-checked here for defence-in-depth after any param mutation above).
    if !csr_info.common_name.is_empty() {
        check_domain_allowed(role, &csr_info.common_name)?;
    }

    // Sign the CSR with the CA key.
    let ca_key_pair =
        KeyPair::from_pem(ca_key_pem).map_err(|e| PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA private key: {e}"),
        })?;

    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem).map_err(|e| {
        PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA cert: {e}"),
        }
    })?;

    let ca_cert =
        ca_params
            .self_signed(&ca_key_pair)
            .map_err(|e| PkiError::CertGenerationFailed {
                reason: format!("failed to reconstruct CA cert: {e}"),
            })?;

    // `CertificateSigningRequestParams::signed_by` takes (self, issuer, issuer_key).
    let signed_cert =
        csr.signed_by(&ca_cert, &ca_key_pair)
            .map_err(|e| PkiError::CertGenerationFailed {
                reason: format!("CSR signing failed: {e}"),
            })?;

    Ok(SignCsrOutput {
        cert_pem: signed_cert.pem(),
        ca_chain_pem: ca_cert_pem.to_string(),
        serial,
        not_after,
    })
}

// ---------------------------------------------------------------------------
// CRL generation
// ---------------------------------------------------------------------------

/// Build a minimal CRL in PEM format listing the provided revoked certificates.
///
/// Each entry contains the serial (hex-decoded to bytes) and the revocation
/// timestamp.  The CRL is signed by the CA and valid for 24 hours from `now`.
pub fn build_crl_pem(
    ca_cert_pem: &str,
    ca_key_pem: &Zeroizing<String>,
    revoked: &[(String, DateTime<Utc>)],
) -> Result<String, PkiError> {
    use rcgen::{CertificateRevocationListParams, RevokedCertParams};

    let ca_key_pair =
        KeyPair::from_pem(ca_key_pem).map_err(|e| PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA key for CRL signing: {e}"),
        })?;

    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem).map_err(|e| {
        PkiError::CertGenerationFailed {
            reason: format!("failed to parse CA cert for CRL: {e}"),
        }
    })?;

    let ca_cert =
        ca_params
            .self_signed(&ca_key_pair)
            .map_err(|e| PkiError::CertGenerationFailed {
                reason: format!("failed to reconstruct CA cert for CRL: {e}"),
            })?;

    let now = Utc::now();
    let next_update = now + Duration::hours(24);

    let mut revoked_certs: Vec<RevokedCertParams> = Vec::new();

    for (serial_hex, revoked_at) in revoked {
        let serial_bytes = hex::decode(serial_hex).map_err(|_| PkiError::CertGenerationFailed {
            reason: format!("invalid serial hex in revocation list: {serial_hex}"),
        })?;

        revoked_certs.push(RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(&serial_bytes),
            revocation_time: rcgen_time(*revoked_at),
            reason_code: None,
            invalidity_date: None,
        });
    }

    let crl_params = CertificateRevocationListParams {
        this_update: rcgen_time(now),
        next_update: rcgen_time(next_update),
        crl_number: rcgen::SerialNumber::from_slice(&[0x01]),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params.signed_by(&ca_cert, &ca_key_pair).map_err(|e| {
        PkiError::CertGenerationFailed {
            reason: format!("CRL signing failed: {e}"),
        }
    })?;

    crl.pem().map_err(|e| PkiError::CertGenerationFailed {
        reason: format!("CRL PEM serialization failed: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Domain constraint enforcement
// ---------------------------------------------------------------------------

/// Information extracted from a parsed CSR for constraint checking.
struct CsrInfo {
    common_name: String,
    /// DNS SANs validated by `parse_and_validate_csr`; retained for future use
    /// (e.g. returning the list to callers or logging).
    #[allow(dead_code)]
    dns_sans: Vec<String>,
}

/// Parse a PEM CSR with x509-parser and extract the CN + DNS SANs for
/// constraint validation.
fn parse_and_validate_csr(role: &PkiRole, csr_pem: &str) -> Result<CsrInfo, PkiError> {
    use x509_parser::prelude::*;

    // Strip the PEM armor to get DER bytes.
    // Use pem::parse from the standalone `pem` crate (v3).
    let pem_block = ::pem::parse(csr_pem).map_err(|e| PkiError::InvalidCsr {
        reason: format!("PEM decode failed: {e}"),
    })?;

    let (_, csr) = X509CertificationRequest::from_der(pem_block.contents()).map_err(|e| {
        PkiError::InvalidCsr {
            reason: format!("DER parse failed: {e}"),
        }
    })?;

    csr.verify_signature().map_err(|e| PkiError::InvalidCsr {
        reason: format!("CSR signature verification failed: {e}"),
    })?;

    // Extract CN.
    let common_name = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("")
        .to_string();

    // Validate CN against role.
    if !common_name.is_empty() {
        check_domain_allowed(role, &common_name)?;
    }

    // Extract DNS SANs from the attributes/extensions embedded in the CSR.
    let mut dns_sans: Vec<String> = Vec::new();

    for attr in csr.certification_request_info.attributes().iter() {
        if let ParsedCriAttribute::ExtensionRequest(extensions) = attr.parsed_attribute() {
            for ext in extensions.extensions.iter() {
                if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                    for name in san.general_names.iter() {
                        match name {
                            GeneralName::DNSName(dns) => {
                                check_domain_allowed(role, dns)?;
                                dns_sans.push(dns.to_string());
                            }
                            GeneralName::IPAddress(_) if !role.allow_ip_sans => {
                                return Err(PkiError::RoleConstraintViolated {
                                    reason: "role does not allow IP SANs".into(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(CsrInfo {
        common_name,
        dns_sans,
    })
}

/// Check whether `name` satisfies the domain policy encoded in `role`.
///
/// A name is accepted if any of the following holds for at least one entry in
/// `role.allowed_domains`:
///
/// - `allow_bare_domains` is true and `name` exactly matches the entry.
/// - `allow_subdomains` is true and `name` ends with `".<entry>"`.
///
/// Returns `PkiError::RoleConstraintViolated` if no rule matches.
fn check_domain_allowed(role: &PkiRole, name: &str) -> Result<(), PkiError> {
    // Normalise to lowercase for case-insensitive matching.
    let name_lc = name.to_lowercase();

    for allowed in &role.allowed_domains {
        let allowed_lc = allowed.to_lowercase();

        // Bare-domain match.
        if role.allow_bare_domains && name_lc == allowed_lc {
            return Ok(());
        }

        // Subdomain match: name must end with ".<allowed>".
        if role.allow_subdomains && name_lc.ends_with(&format!(".{}", allowed_lc)) {
            return Ok(());
        }

        // Wildcard leaf: "*.example.com" in the role allows "foo.example.com".
        if allowed_lc.starts_with("*.") {
            let suffix = &allowed_lc[1..]; // ".example.com"
            if name_lc.ends_with(suffix) && !name_lc[..name_lc.len() - suffix.len()].contains('.') {
                return Ok(());
            }
        }
    }

    Err(PkiError::RoleConstraintViolated {
        reason: format!(
            "name '{}' is not permitted by the role's allowed_domains policy",
            name
        ),
    })
}

// ---------------------------------------------------------------------------
// Time conversion helper
// ---------------------------------------------------------------------------

/// Convert a `chrono::DateTime<Utc>` to the `time::OffsetDateTime` that rcgen requires.
fn rcgen_time(dt: DateTime<Utc>) -> OffsetDateTime {
    let ts = dt.timestamp();
    OffsetDateTime::from_unix_timestamp(ts)
        .expect("timestamp from chrono::Utc::now() must be valid")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyType, KeyUsage, PkiRole};
    use chrono::Utc;

    fn test_role(
        allowed_domains: Vec<&str>,
        allow_subdomains: bool,
        allow_bare_domains: bool,
    ) -> PkiRole {
        PkiRole {
            tenant_id: "test-tenant".into(),
            name: "test".into(),
            allowed_domains: allowed_domains.into_iter().map(String::from).collect(),
            allow_subdomains,
            allow_bare_domains,
            max_ttl_seconds: 86400,
            key_type: KeyType::EcdsaP256,
            key_usages: vec![KeyUsage::ServerAuth],
            allow_ip_sans: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ---- CA generation -------------------------------------------------------

    #[test]
    fn generate_ca_ecdsa_p256_roundtrip() {
        let output = generate_ca("Test CA", 3600, &KeyType::EcdsaP256).unwrap();
        assert!(!output.cert_pem.is_empty());
        assert!(!output.key_pem.is_empty());
        assert_eq!(output.serial.len(), 16); // 8 bytes → 16 hex chars
    }

    /// RSA key generation via rcgen requires the `aws_lc_rs` backend; the
    /// default `ring` backend does not support it.  This test is ignored unless
    /// the crate is compiled with `--features aws_lc_rs`.
    #[test]
    #[ignore = "RSA generation requires rcgen aws_lc_rs feature; ring backend supports ECDSA only"]
    fn generate_ca_rsa2048_roundtrip() {
        let output = generate_ca("RSA CA", 3600, &KeyType::Rsa2048).unwrap();
        assert!(!output.cert_pem.is_empty());
    }

    // ---- Leaf issuance -------------------------------------------------------

    fn setup_ca() -> (String, Zeroizing<String>) {
        let ca = generate_ca("Issuer CA", 3600 * 24 * 365, &KeyType::EcdsaP256).unwrap();
        (ca.cert_pem, ca.key_pem)
    }

    #[test]
    fn issue_leaf_basic_roundtrip() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], true, true);

        let out = issue_leaf(&ca_cert, &ca_key, &role, "api.example.com", &[], &[], 3600).unwrap();

        assert!(!out.cert_pem.is_empty());
        assert!(!out.private_key_pem.is_empty());
        assert_eq!(out.ca_chain_pem, ca_cert);
        assert!(!out.serial.is_empty());
        // Expiry should be roughly now + 3600 s.
        assert!(out.not_after > Utc::now());
    }

    #[test]
    fn issue_leaf_ttl_capped_to_role_max() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], true, true);

        // Request a TTL longer than role maximum; it should be silently capped.
        let out = issue_leaf(
            &ca_cert,
            &ca_key,
            &role,
            "api.example.com",
            &[],
            &[],
            9999999,
        )
        .unwrap();

        let expected_max = Utc::now() + chrono::Duration::seconds(role.max_ttl_seconds + 5);
        assert!(
            out.not_after < expected_max,
            "TTL must be capped to role max"
        );
    }

    #[test]
    fn issue_leaf_rejects_unlisted_domain() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], false, true);

        let result = issue_leaf(
            &ca_cert,
            &ca_key,
            &role,
            "evil.attacker.com",
            &[],
            &[],
            3600,
        );

        assert!(
            matches!(result, Err(PkiError::RoleConstraintViolated { .. })),
            "unlisted domain must be rejected"
        );
    }

    #[test]
    fn issue_leaf_subdomain_allowed_when_flag_set() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], true, false);

        let out = issue_leaf(&ca_cert, &ca_key, &role, "sub.example.com", &[], &[], 3600).unwrap();
        assert!(!out.cert_pem.is_empty());
    }

    #[test]
    fn issue_leaf_bare_domain_rejected_when_flag_unset() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], true, false);

        let result = issue_leaf(&ca_cert, &ca_key, &role, "example.com", &[], &[], 3600);

        assert!(
            matches!(result, Err(PkiError::RoleConstraintViolated { .. })),
            "bare domain must be rejected when allow_bare_domains is false"
        );
    }

    #[test]
    fn issue_leaf_ip_san_rejected_by_role() {
        let (ca_cert, ca_key) = setup_ca();
        let mut role = test_role(vec!["example.com"], true, true);
        role.allow_ip_sans = false;

        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let result = issue_leaf(
            &ca_cert,
            &ca_key,
            &role,
            "api.example.com",
            &[],
            &[ip],
            3600,
        );

        assert!(
            matches!(result, Err(PkiError::RoleConstraintViolated { .. })),
            "IP SAN must be rejected when allow_ip_sans is false"
        );
    }

    #[test]
    fn issue_leaf_ip_san_allowed_when_flag_set() {
        let (ca_cert, ca_key) = setup_ca();
        let mut role = test_role(vec!["example.com"], true, true);
        role.allow_ip_sans = true;

        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let out = issue_leaf(
            &ca_cert,
            &ca_key,
            &role,
            "api.example.com",
            &[],
            &[ip],
            3600,
        )
        .unwrap();
        assert!(!out.cert_pem.is_empty());
    }

    // ---- CRL -----------------------------------------------------------------

    #[test]
    fn build_crl_empty_revocation_list() {
        let (ca_cert, ca_key) = setup_ca();
        let crl_pem = build_crl_pem(&ca_cert, &ca_key, &[]).unwrap();
        assert!(crl_pem.contains("BEGIN X509 CRL"));
    }

    #[test]
    fn build_crl_with_revoked_cert() {
        let (ca_cert, ca_key) = setup_ca();
        let serial = generate_serial();
        let revoked_at = Utc::now();
        let crl_pem = build_crl_pem(&ca_cert, &ca_key, &[(serial.clone(), revoked_at)]).unwrap();
        assert!(crl_pem.contains("BEGIN X509 CRL"));
    }

    // ---- CSR signing ---------------------------------------------------------

    #[test]
    fn sign_csr_roundtrip() {
        let (ca_cert, ca_key) = setup_ca();
        let role = test_role(vec!["example.com"], true, true);

        // Generate a CSR using rcgen.
        let csr_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut csr_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "api.example.com");
        csr_params.distinguished_name = dn;
        csr_params.subject_alt_names =
            vec![SanType::DnsName("api.example.com".try_into().unwrap())];
        let csr_pem = csr_params
            .serialize_request(&csr_key)
            .unwrap()
            .pem()
            .unwrap();

        let out = sign_csr(&ca_cert, &ca_key, &role, &csr_pem, 3600).unwrap();
        assert!(!out.cert_pem.is_empty());
        assert!(!out.serial.is_empty());
    }

    // ---- Domain constraint helpers ------------------------------------------

    #[test]
    fn bare_domain_allowed_when_flag_set() {
        let role = test_role(vec!["example.com"], false, true);
        assert!(check_domain_allowed(&role, "example.com").is_ok());
    }

    #[test]
    fn subdomain_rejected_when_only_bare_domain_allowed() {
        let role = test_role(vec!["example.com"], false, true);
        assert!(check_domain_allowed(&role, "sub.example.com").is_err());
    }

    #[test]
    fn subdomain_allowed_when_flag_set() {
        let role = test_role(vec!["example.com"], true, false);
        assert!(check_domain_allowed(&role, "sub.example.com").is_ok());
        assert!(check_domain_allowed(&role, "deep.sub.example.com").is_ok());
    }

    #[test]
    fn unlisted_domain_always_rejected() {
        let role = test_role(vec!["example.com"], true, true);
        assert!(check_domain_allowed(&role, "attacker.com").is_err());
        assert!(check_domain_allowed(&role, "notexample.com").is_err());
    }
}
