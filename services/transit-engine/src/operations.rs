//! Transit cryptographic operations.
//!
//! All symmetric encryption delegates to `wslvault_core::crypto::envelope` for
//! AES-256-GCM so that the cipher implementation is centralised and tested in
//! the core crate.  HMAC-SHA256 signing uses `ring::hmac` directly.
//!
//! Ciphertext wire format for versioned transit:
//!   `vault:v{VERSION}:{BASE64(nonce || ciphertext || tag)}`
//!
//! The version prefix is mandatory so that `decrypt` and `rewrap` can locate
//! the correct key version.

use ring::hmac;
use zeroize::Zeroizing;

use wslvault_core::crypto::envelope::{decrypt_with_dek, encrypt_with_dek};
use wslvault_core::VaultError;

use crate::key_store::TransitKey;

/// Version prefix prepended to all transit ciphertexts.
const CIPHERTEXT_PREFIX: &str = "vault:v";

/// Encrypt `plaintext` under the latest version of `key`.
///
/// Returns a versioned ciphertext string of the form:
/// `vault:v{VERSION}:{BASE64_ENVELOPE}`
pub fn encrypt(key: &TransitKey, plaintext: &[u8]) -> Result<String, VaultError> {
    let dek = key.current_material();
    // Use the key name as AAD to bind the ciphertext to this specific key,
    // preventing ciphertexts from being transplanted between keys.
    let aad = key.name.as_bytes();

    let envelope = encrypt_with_dek(dek, plaintext, aad)?;

    Ok(format!(
        "{}{}:{}",
        CIPHERTEXT_PREFIX, key.current_version, envelope.ciphertext_b64
    ))
}

/// Decrypt a versioned ciphertext produced by `encrypt`.
///
/// Parses the version from the prefix, locates the appropriate key version,
/// and decrypts using AES-256-GCM.
pub fn decrypt(key: &TransitKey, versioned_ciphertext: &str) -> Result<Vec<u8>, VaultError> {
    let (version, b64_body) = parse_versioned_ciphertext(versioned_ciphertext)?;

    let dek = key
        .material_for_version(version)
        .ok_or_else(|| VaultError::KeyNotFound {
            key_id: format!("{}:v{}", key.name, version),
        })?;

    let aad = key.name.as_bytes();
    let plaintext = decrypt_with_dek(dek, b64_body, aad)?;
    Ok(plaintext.to_vec())
}

/// Derive the MAC subkey for a transit key.
///
/// `sign_data` and `verify_data` used the key's raw material directly — the
/// same 32 bytes that AES-256-GCM encrypts with. Using one key for two
/// primitives is a hygiene failure: it removes the domain separation that
/// keeps a weakness or a misuse in one construction from bearing on the other.
///
/// HKDF-SHA256 with a distinct context gives each primitive its own key, from
/// the same stored material and with no schema change. `wslvault-core` already
/// ships the KDF.
///
/// Note this changes the signatures a given key produces. `/sign` and `/verify`
/// are HMAC — a shared-secret MAC, not a digital signature — so a signature is
/// only ever verifiable by a holder of the key, and there are no third-party
/// verifiers to break. Anything persisted from before must be re-signed.
fn mac_subkey(key_material: &[u8]) -> Zeroizing<[u8; 32]> {
    wslvault_core::crypto::kdf::derive_key(key_material, None, b"wslvault:transit:mac:v1")
        .expect("HKDF-SHA256 cannot fail for a 32-byte output")
}

/// Compute an HMAC-SHA256 signature over `data`.
///
/// Returns a hex-encoded signature string.
pub fn sign_data(key: &[u8], data: &[u8]) -> String {
    let mac_key = mac_subkey(key);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key.as_ref());
    let tag = hmac::sign(&signing_key, data);
    hex::encode(tag.as_ref())
}

/// Verify that `signature` matches the HMAC-SHA256 of `data` under `key`.
///
/// Uses constant-time comparison via `ring::hmac::verify` to prevent
/// timing-based signature forgery.
pub fn verify_data(key: &[u8], data: &[u8], signature: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };
    let mac_key = mac_subkey(key);
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key.as_ref());
    hmac::verify(&verification_key, data, &sig_bytes).is_ok()
}

// ---------------------------------------------------------------------------
// Ed25519 (asymmetric) signing
// ---------------------------------------------------------------------------

/// Prefix of a versioned signature, the same shape as a transit ciphertext:
/// `vault:v{VERSION}:{BASE64URL(signature)}`. The version tells a verifier,
/// or `verify`, which key version produced it after a rotation.
const SIGNATURE_PREFIX: &str = "vault:v";

fn ed25519_pair(seed: &[u8; 32]) -> ring::signature::Ed25519KeyPair {
    // `from_seed_unchecked` derives the public key from the seed itself, so
    // there is no stored public half that could disagree with it.
    ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .expect("any 32-byte seed is a valid Ed25519 private key")
}

/// The 32-byte Ed25519 public key for a seed.
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    use ring::signature::KeyPair as _;
    let mut out = [0u8; 32];
    out.copy_from_slice(ed25519_pair(seed).public_key().as_ref());
    out
}

/// A signature from Ed25519 transit signing.
pub struct Ed25519Signature {
    /// The 64 raw signature bytes.
    pub raw: Vec<u8>,
    /// Which key version signed.
    pub key_version: u32,
}

impl Ed25519Signature {
    /// `vault:v{N}:{base64url}`. Base64url without padding, so the value after
    /// the last `:` can be used directly as the third part of a compact JWS.
    pub fn versioned(&self) -> String {
        format!(
            "{SIGNATURE_PREFIX}{}:{}",
            self.key_version,
            b64url(&self.raw)
        )
    }
}

/// Sign `data` with a specific version of an Ed25519 key, or with the current
/// version when `version` is `None`.
pub fn ed25519_sign(
    key: &TransitKey,
    data: &[u8],
    version: Option<u32>,
) -> Result<Ed25519Signature, VaultError> {
    let key_version = version.unwrap_or(key.current_version);
    let seed = key
        .material_for_version(key_version)
        .ok_or_else(|| VaultError::KeyNotFound {
            key_id: format!("{}:v{}", key.name, key_version),
        })?;
    let sig = ed25519_pair(seed).sign(data);
    Ok(Ed25519Signature {
        raw: sig.as_ref().to_vec(),
        key_version,
    })
}

/// Verify a `vault:v{N}:{base64url}` signature against version N of the key.
///
/// Returns false, never an error, for anything malformed, a version the key
/// does not have, or a signature that does not verify, so that the endpoint
/// leaks nothing beyond "valid" or "not valid".
pub fn ed25519_verify(key: &TransitKey, data: &[u8], signature: &str) -> bool {
    let Some(rest) = signature.strip_prefix(SIGNATURE_PREFIX) else {
        return false;
    };
    let Some((version, body)) = rest.split_once(':') else {
        return false;
    };
    let Ok(version) = version.parse::<u32>() else {
        return false;
    };
    let Some(seed) = key.material_for_version(version) else {
        return false;
    };
    let Some(sig) = b64url_decode(body) else {
        return false;
    };
    let public = ed25519_public_key(seed);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(data, &sig)
        .is_ok()
}

/// The JWK `kid` for one version of a key: `{key_name}:v{N}`.
pub fn jwk_kid(key_name: &str, version: u32) -> String {
    format!("{key_name}:v{version}")
}

/// Every version's public key as an RFC 8037 OKP JWK, oldest first.
///
/// All versions are published, not only the current one: tokens signed just
/// before a rotation are still in flight and must stay verifiable until they
/// expire. Retiring an old version is a separate, deliberate step.
pub fn ed25519_jwks(key: &TransitKey) -> serde_json::Value {
    let keys: Vec<serde_json::Value> = key
        .versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64url(&ed25519_public_key(&v.material)),
                "kid": jwk_kid(&key.name, v.version),
                "use": "sig",
                "alg": "EdDSA",
            })
        })
        .collect();
    serde_json::json!({ "keys": keys })
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

// ---------------------------------------------------------------------------
// Versioned HMAC
// ---------------------------------------------------------------------------

/// HMAC-SHA256 over `data` with a specific version of a symmetric key (the
/// current one when `version` is `None`), as `vault:v{N}:{hex}`.
///
/// Versioned on purpose. The un-versioned `sign_data` uses the current version
/// only, so every stored MAC stops matching after a rotation. A caller that
/// keeps MACs (for example opsapi storing `HMAC(agent secret)`) records the
/// version and recomputes under it.
pub fn hmac_versioned(
    key: &TransitKey,
    data: &[u8],
    version: Option<u32>,
) -> Result<(String, u32), VaultError> {
    let key_version = version.unwrap_or(key.current_version);
    let material =
        key.material_for_version(key_version)
            .ok_or_else(|| VaultError::KeyNotFound {
                key_id: format!("{}:v{}", key.name, key_version),
            })?;
    Ok((
        format!(
            "{SIGNATURE_PREFIX}{key_version}:{}",
            sign_data(material, data)
        ),
        key_version,
    ))
}

/// Rewrap a ciphertext by decrypting with the old key version and re-encrypting
/// with the current (latest) version.
///
/// This is used during key rotation to upgrade existing ciphertexts without
/// exposing the plaintext beyond the service boundary.
pub fn rewrap(key: &TransitKey, old_ciphertext: &str) -> Result<String, VaultError> {
    let plaintext = decrypt(key, old_ciphertext)?;
    encrypt(key, &plaintext)
}

/// Parse a versioned ciphertext string into `(version, base64_body)`.
///
/// Expected format: `vault:v{N}:{BASE64}`
fn parse_versioned_ciphertext(ciphertext: &str) -> Result<(u32, &str), VaultError> {
    // Strip the mandatory "vault:v" prefix.
    let after_prefix = ciphertext
        .strip_prefix(CIPHERTEXT_PREFIX)
        .ok_or_else(|| VaultError::DecryptionFailed)?;

    // Split into version and b64 body at the first `:`.
    let colon_pos = after_prefix.find(':').ok_or(VaultError::DecryptionFailed)?;

    let version_str = &after_prefix[..colon_pos];
    let b64_body = &after_prefix[colon_pos + 1..];

    let version: u32 = version_str
        .parse()
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok((version, b64_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_store::{KeyAlgorithm, KeyVersion, TransitKey};
    use chrono::Utc;

    fn make_key(name: &str) -> TransitKey {
        TransitKey {
            name: name.to_string(),
            versions: vec![KeyVersion {
                version: 1,
                material: [0x42u8; 32],
            }],
            current_version: 1,
            algorithm: KeyAlgorithm::Aes256Gcm,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = make_key("my-key");
        let plaintext = b"hello transit";
        let ct = encrypt(&key, plaintext).unwrap();
        assert!(ct.starts_with("vault:v1:"));
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key_bytes = b"test-hmac-key-must-be-long-enough";
        let data = b"data to sign";
        let sig = sign_data(key_bytes, data);
        assert!(verify_data(key_bytes, data, &sig));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key_bytes = b"test-hmac-key-must-be-long-enough";
        let wrong_key = b"different-key-also-must-be-long!!";
        let data = b"data to sign";
        let sig = sign_data(key_bytes, data);
        assert!(!verify_data(wrong_key, data, &sig));
    }

    #[test]
    fn rewrap_produces_new_ciphertext() {
        let mut key = make_key("my-key");
        let plaintext = b"secret data";
        let old_ct = encrypt(&key, plaintext).unwrap();

        // Add a new key version.
        key.versions.push(KeyVersion {
            version: 2,
            material: [0xABu8; 32],
        });
        key.current_version = 2;

        let new_ct = rewrap(&key, &old_ct).unwrap();
        assert!(new_ct.starts_with("vault:v2:"));

        let pt = decrypt(&key, &new_ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// The MAC key must not be the encryption key. Sharing one key between
    /// AES-GCM and HMAC removes the domain separation between them.
    #[test]
    fn mac_key_is_separated_from_the_encryption_key() {
        let material = [0x42u8; 32];
        assert_ne!(
            *mac_subkey(&material),
            material,
            "the MAC subkey must be derived, not the raw encryption key"
        );
    }

    #[test]
    fn mac_subkey_is_deterministic_and_key_specific() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_eq!(*mac_subkey(&a), *mac_subkey(&a));
        assert_ne!(*mac_subkey(&a), *mac_subkey(&b));
    }

    // -----------------------------------------------------------------------
    // Ed25519
    // -----------------------------------------------------------------------

    fn ed_key(name: &str, seeds: &[[u8; 32]]) -> TransitKey {
        TransitKey {
            name: name.to_string(),
            versions: seeds
                .iter()
                .enumerate()
                .map(|(i, s)| KeyVersion {
                    version: i as u32 + 1,
                    material: *s,
                })
                .collect(),
            current_version: seeds.len() as u32,
            algorithm: KeyAlgorithm::Ed25519,
            created_at: Utc::now(),
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 8032 §7.1, test 1. Proves the seed is interpreted as a standard
    /// Ed25519 private key, so any compliant verifier agrees with us.
    #[test]
    fn ed25519_matches_rfc8032_test_vector_1() {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&unhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        assert_eq!(
            ed25519_public_key(&seed).to_vec(),
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = ed25519_sign(&ed_key("k", &[seed]), b"", None).unwrap();
        assert_eq!(
            sig.raw,
            unhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        assert_eq!(sig.key_version, 1);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip_and_tamper() {
        let key = ed_key("idp", &[[7u8; 32]]);
        let sig = ed25519_sign(&key, b"claims", None).unwrap().versioned();
        assert!(sig.starts_with("vault:v1:"));
        assert!(ed25519_verify(&key, b"claims", &sig));
        assert!(
            !ed25519_verify(&key, b"claimz", &sig),
            "altered data must fail"
        );

        let other = ed_key("idp", &[[8u8; 32]]);
        assert!(
            !ed25519_verify(&other, b"claims", &sig),
            "another key must fail"
        );

        for junk in [
            "",
            "vault:v1:",
            "vault:vX:abc",
            "vault:v9:AAAA",
            "nonsense",
            "vault:v1:!!!",
        ] {
            assert!(
                !ed25519_verify(&key, b"claims", junk),
                "{junk:?} must not verify"
            );
        }
    }

    /// After rotation, signatures from the previous version still verify (they
    /// are in flight until they expire) and new ones use the new version.
    #[test]
    fn ed25519_rotation_keeps_old_signatures_verifiable() {
        let v1_only = ed_key("idp", &[[1u8; 32]]);
        let old_sig = ed25519_sign(&v1_only, b"t", None).unwrap().versioned();

        let rotated = ed_key("idp", &[[1u8; 32], [2u8; 32]]);
        assert!(ed25519_verify(&rotated, b"t", &old_sig));

        let new_sig = ed25519_sign(&rotated, b"t", None).unwrap();
        assert_eq!(new_sig.key_version, 2);
        assert!(ed25519_verify(&rotated, b"t", &new_sig.versioned()));

        let pinned = ed25519_sign(&rotated, b"t", Some(1)).unwrap();
        assert_eq!(
            pinned.versioned(),
            old_sig,
            "Ed25519 is deterministic per version"
        );
        assert!(ed25519_sign(&rotated, b"t", Some(3)).is_err());
    }

    #[test]
    fn jwks_publishes_every_version_and_no_private_material() {
        let seeds = [[1u8; 32], [2u8; 32]];
        let key = ed_key("agent-idp", &seeds);
        let jwks = ed25519_jwks(&key);
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(k["kty"], "OKP");
            assert_eq!(k["crv"], "Ed25519");
            assert_eq!(k["alg"], "EdDSA");
            assert_eq!(k["use"], "sig");
            assert_eq!(k["kid"], format!("agent-idp:v{}", i + 1));
            assert!(
                k.get("d").is_none(),
                "the private part of an OKP JWK is 'd'"
            );
        }
        let text = jwks.to_string();
        for seed in &seeds {
            assert!(
                !text.contains(&b64url(seed)),
                "a seed must never be published"
            );
        }
    }

    /// End to end: build a compact JWS the way opsapi will (header and claims
    /// base64url, signed by transit), then verify it with `jsonwebtoken` using
    /// only the published JWK. This is the relying-party path.
    #[test]
    fn transit_signature_is_a_valid_jws_for_an_independent_verifier() {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let key = ed_key("agent-idp", &[[0x5au8; 32]]);
        let kid = jwk_kid("agent-idp", 1);
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let claims = serde_json::json!({
            "iss": "https://opsapi.example",
            "sub": "agent:7f1c",
            "aud": "opsapi",
            "exp": 4102444800i64,
        });
        let signing_input = format!(
            "{}.{}",
            b64url(header.to_string().as_bytes()),
            b64url(claims.to_string().as_bytes())
        );
        let sig = ed25519_sign(&key, signing_input.as_bytes(), None).unwrap();
        let versioned = sig.versioned();
        let sig_part = versioned.rsplit(':').next().unwrap();
        let jws = format!("{signing_input}.{sig_part}");

        let jwks = ed25519_jwks(&key);
        let x = jwks["keys"][0]["x"].as_str().unwrap();
        let decoding = DecodingKey::from_ed_components(x).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["opsapi"]);
        validation.set_issuer(&["https://opsapi.example"]);

        let decoded = decode::<serde_json::Value>(&jws, &decoding, &validation).unwrap();
        assert_eq!(decoded.claims["sub"], "agent:7f1c");
        assert_eq!(decoded.header.kid.as_deref(), Some(kid.as_str()));

        // And a forged token (claims changed, signature kept) is rejected.
        let forged_claims = b64url(br#"{"iss":"https://opsapi.example","sub":"agent:evil","aud":"opsapi","exp":4102444800}"#);
        let forged = format!(
            "{}.{forged_claims}.{sig_part}",
            b64url(header.to_string().as_bytes())
        );
        assert!(decode::<serde_json::Value>(&forged, &decoding, &validation).is_err());
    }

    // -----------------------------------------------------------------------
    // Versioned HMAC
    // -----------------------------------------------------------------------

    /// A stored MAC stays checkable after rotation by recomputing under the
    /// version recorded with it; the un-versioned `sign_data` cannot do that.
    #[test]
    fn hmac_versioned_survives_rotation() {
        let mut key = make_key("agent-secret");
        let (mac_v1, v) = hmac_versioned(&key, b"opsa_secret", None).unwrap();
        assert_eq!(v, 1);
        assert!(mac_v1.starts_with("vault:v1:"));

        key.versions.push(KeyVersion {
            version: 2,
            material: [0x43u8; 32],
        });
        key.current_version = 2;

        let (again_v1, _) = hmac_versioned(&key, b"opsa_secret", Some(1)).unwrap();
        assert_eq!(again_v1, mac_v1);
        let (mac_v2, v2) = hmac_versioned(&key, b"opsa_secret", None).unwrap();
        assert_eq!(v2, 2);
        assert_ne!(mac_v2, mac_v1);
        assert!(hmac_versioned(&key, b"x", Some(9)).is_err());
    }
}
