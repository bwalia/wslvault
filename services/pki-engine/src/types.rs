//! Shared domain types for the PKI engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

/// Supported asymmetric key types for CA and leaf certificate generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// ECDSA with NIST P-256 curve (default; compact and fast).
    #[default]
    EcdsaP256,
    /// RSA with 2048-bit modulus.
    Rsa2048,
    /// RSA with 4096-bit modulus (stronger but slower signing/verification).
    Rsa4096,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::Rsa2048 => "rsa-2048",
            KeyType::Rsa4096 => "rsa-4096",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for KeyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa-p256" | "ec" | "ecdsa" => Ok(KeyType::EcdsaP256),
            "rsa-2048" | "rsa2048" => Ok(KeyType::Rsa2048),
            "rsa-4096" | "rsa4096" => Ok(KeyType::Rsa4096),
            other => Err(format!("unknown key type: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Key usage flags
// ---------------------------------------------------------------------------

/// X.509 extended key usage values that may be included in a role or certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

// ---------------------------------------------------------------------------
// In-memory / transfer representations of store rows
// ---------------------------------------------------------------------------

/// A CA record for a single tenant, as stored in `pki_ca`.
#[derive(Debug, Clone)]
pub struct TenantCa {
    pub tenant_id: String,
    /// PEM-encoded CA certificate.
    pub cert_pem: String,
    /// AES-256-GCM envelope (base64) of the CA private key, encrypted under
    /// the service-level root KEK loaded from `PKI_ROOT_KEY`.
    pub encrypted_key_b64: String,
    /// Version number of the root KEK used to wrap `encrypted_key_b64`.
    /// Stored so future key rotation can re-wrap without a CA re-issue.
    pub key_version: i32,
    pub created_at: DateTime<Utc>,
}

/// A PKI role record, as stored in `pki_roles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiRole {
    pub tenant_id: String,
    pub name: String,
    /// Domains that leaf certificates are allowed to use as CNs / SANs.
    pub allowed_domains: Vec<String>,
    /// Allow subdomain suffixes of `allowed_domains` in SANs.
    pub allow_subdomains: bool,
    /// Allow the bare domain itself (not just subdomains) as a SAN.
    pub allow_bare_domains: bool,
    /// Maximum certificate lifetime in seconds.  Leaf TTL is capped to this.
    pub max_ttl_seconds: i64,
    pub key_type: KeyType,
    pub key_usages: Vec<KeyUsage>,
    /// Allow IP address SANs in issued certificates.
    pub allow_ip_sans: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row from `pki_certs`.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub id: String,
    pub tenant_id: String,
    pub role_name: String,
    /// X.509 serial number, hex-encoded (lowercase), e.g. "0a1b2c3d".
    pub serial: String,
    pub common_name: String,
    pub not_after: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
