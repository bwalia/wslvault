//! Criterion benchmarks for the wslvault-core cryptographic primitives.
//!
//! Covers:
//!   - AES-256-GCM envelope encrypt / decrypt at 1 KB, 16 KB, 256 KB
//!   - HKDF-SHA256 key derivation
//!   - CSPRNG nonce generation
//!
//! Run with:
//!   cargo bench -p wslvault-core
//!
//! Results land in target/criterion/. HTML reports open automatically if a
//! browser is available.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use wslvault_core::crypto::{
    envelope::{decrypt_with_dek, encrypt_with_dek},
    kdf::derive_key,
    nonce::generate_aes_gcm_nonce,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Returns a deterministic 32-byte DEK. Never use outside tests/benchmarks.
fn bench_dek() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(0x5A);
    }
    k
}

/// Build a plaintext payload of exactly `size_bytes` bytes.
fn build_payload(size_bytes: usize) -> Vec<u8> {
    (0..size_bytes).map(|i| (i & 0xFF) as u8).collect()
}

// ── AES-256-GCM envelope encrypt ─────────────────────────────────────────────

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let dek = bench_dek();
    let aad = b"tenant-bench:prod/database/password";

    let mut group = c.benchmark_group("aes256gcm/encrypt");

    for &size in &[1_024usize, 16_384, 262_144] {
        let payload = build_payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &payload,
            |b, p| {
                b.iter(|| {
                    encrypt_with_dek(black_box(&dek), black_box(p), black_box(aad)).unwrap()
                });
            },
        );
    }

    group.finish();
}

// ── AES-256-GCM envelope decrypt ─────────────────────────────────────────────

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let dek = bench_dek();
    let aad = b"tenant-bench:prod/database/password";

    let mut group = c.benchmark_group("aes256gcm/decrypt");

    for &size in &[1_024usize, 16_384, 262_144] {
        let payload = build_payload(size);
        // Pre-encrypt once so the decrypt bench operates on real ciphertext.
        let envelope = encrypt_with_dek(&dek, &payload, aad).unwrap();
        let ciphertext_b64 = envelope.ciphertext_b64.clone();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &ciphertext_b64,
            |b, ct| {
                b.iter(|| {
                    decrypt_with_dek(black_box(&dek), black_box(ct.as_str()), black_box(aad))
                        .unwrap()
                });
            },
        );
    }

    group.finish();
}

// ── HKDF-SHA256 key derivation ────────────────────────────────────────────────

fn bench_hkdf_derive_key(c: &mut Criterion) {
    // Represents a raw TenantKEK being expanded into a per-path DEK.
    let ikm = [0xAB_u8; 32];
    let salt = b"wslvault-bench-salt-v1";
    let info = b"tenant-bench:prod/service/api-key:dek-v1";

    c.bench_function("hkdf_sha256/derive_key_32b", |b| {
        b.iter(|| {
            derive_key(black_box(&ikm), black_box(Some(salt)), black_box(info)).unwrap()
        });
    });
}

// ── CSPRNG nonce generation ───────────────────────────────────────────────────

fn bench_nonce_generation(c: &mut Criterion) {
    // Nonce generation happens on every encrypt call; bench it in isolation
    // to understand its contribution to per-encrypt overhead.
    c.bench_function("csprng/aes_gcm_nonce_12b", |b| {
        b.iter(|| generate_aes_gcm_nonce().unwrap());
    });
}

// ── Criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    crypto_benches,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_hkdf_derive_key,
    bench_nonce_generation,
);
criterion_main!(crypto_benches);
