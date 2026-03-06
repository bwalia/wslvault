//! Cryptographic primitives for the WSLVault platform.
//!
//! All symmetric encryption uses AES-256-GCM (hardware-accelerated via ring/aes-gcm).
//! Key derivation uses HKDF-SHA256. Random nonce generation uses ring's CSPRNG.
//! Raw key material uses ZeroizeOnDrop throughout to prevent secret leakage.

pub mod envelope;
pub mod kdf;
pub mod nonce;
pub mod registry;
