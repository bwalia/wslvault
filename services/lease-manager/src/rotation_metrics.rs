//! Prometheus metrics for the rotation sweep tasks.
//!
//! Metrics are registered lazily with the global `wslvault_core` registry.
//! Each static is a thread-safe `once_cell::Lazy<...>` handle.

use once_cell::sync::Lazy;
use prometheus::{IntCounter, IntCounterVec, Opts};
use wslvault_core::metrics::collector::REGISTRY;

// ---------------------------------------------------------------------------
// Counter: rotation sweep runs
// ---------------------------------------------------------------------------

/// Total number of rotation sweep cycles, labelled by result (success | error).
pub static ROTATION_SWEEP_RUNS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "vault_rotation_sweep_runs_total",
            "Total rotation sweep cycles run by the lease-manager",
        ),
        &["result"],
    )
    .expect("valid metric descriptor");

    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("vault_rotation_sweep_runs_total registration failed");

    counter
});

// ---------------------------------------------------------------------------
// Counter: rotations triggered
// ---------------------------------------------------------------------------

/// Total rotations triggered, labelled by secret_type and result (success | error).
pub static ROTATIONS_TRIGGERED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "vault_rotations_triggered_total",
            "Total secrets for which a rotation was triggered",
        ),
        &["secret_type", "result"],
    )
    .expect("valid metric descriptor");

    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("vault_rotations_triggered_total registration failed");

    counter
});

// ---------------------------------------------------------------------------
// Counter: webhook dispatches
// ---------------------------------------------------------------------------

/// Total webhook dispatch attempts, labelled by result (success | failure).
pub static WEBHOOKS_DISPATCHED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter = IntCounterVec::new(
        Opts::new(
            "vault_webhooks_dispatched_total",
            "Total rotation webhook POST attempts",
        ),
        &["result"],
    )
    .expect("valid metric descriptor");

    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("vault_webhooks_dispatched_total registration failed");

    counter
});

// ---------------------------------------------------------------------------
// Counter: versions revoked
// ---------------------------------------------------------------------------

/// Cumulative count of deprecated secret versions whose ciphertext was
/// destroyed by the cleanup task.
pub static VERSIONS_REVOKED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let counter = IntCounter::new(
        "vault_versions_revoked_total",
        "Total deprecated secret versions revoked (ciphertext destroyed)",
    )
    .expect("valid metric descriptor");

    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("vault_versions_revoked_total registration failed");

    counter
});

/// Force-initialise all rotation metrics lazily.
///
/// Call this once during service startup (before spawning rotation tasks) so
/// that Prometheus returns all metric families from the first scrape even if
/// no rotations have occurred yet.
pub fn init() {
    // Accessing each Lazy forces evaluation and registration.
    let _ = &*ROTATION_SWEEP_RUNS_TOTAL;
    let _ = &*ROTATIONS_TRIGGERED_TOTAL;
    let _ = &*WEBHOOKS_DISPATCHED_TOTAL;
    let _ = &*VERSIONS_REVOKED_TOTAL;
}
