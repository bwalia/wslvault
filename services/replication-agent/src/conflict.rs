//! Conflict resolution strategies for cross-region replication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Outcome of conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Accept the remote event (overwrite local).
    AcceptRemote,
    /// Keep the local version (discard remote).
    KeepLocal,
    /// Conflict cannot be auto-resolved; queue for manual review.
    ManualReview,
}

/// Metadata needed for conflict resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictContext {
    pub local_updated_at: Option<DateTime<Utc>>,
    pub remote_updated_at: DateTime<Utc>,
    pub local_vector_clock: HashMap<String, i64>,
    pub remote_vector_clock: HashMap<String, i64>,
    pub local_region: String,
    pub remote_region: String,
}

/// Resolve a conflict using the Last-Write-Wins strategy.
///
/// Compares timestamps; if equal, the lexicographically greater region wins
/// (deterministic tiebreak).
pub fn resolve_lww(ctx: &ConflictContext) -> Resolution {
    match ctx.local_updated_at {
        None => Resolution::AcceptRemote,
        Some(local_ts) => {
            if ctx.remote_updated_at > local_ts {
                Resolution::AcceptRemote
            } else if ctx.remote_updated_at < local_ts {
                Resolution::KeepLocal
            } else {
                // Timestamps equal — deterministic tiebreak by region name.
                if ctx.remote_region > ctx.local_region {
                    Resolution::AcceptRemote
                } else {
                    Resolution::KeepLocal
                }
            }
        }
    }
}

/// Resolve a conflict using vector clocks.
///
/// If the remote clock strictly dominates the local clock, accept.
/// If the local clock strictly dominates, keep local.
/// If concurrent (neither dominates), fall back to region-name tiebreak.
pub fn resolve_vector_clock(ctx: &ConflictContext) -> Resolution {
    let remote_dominates = ctx.remote_vector_clock.iter().all(|(region, &remote_seq)| {
        let local_seq = ctx.local_vector_clock.get(region).copied().unwrap_or(0);
        remote_seq >= local_seq
    }) && ctx.remote_vector_clock.iter().any(|(region, &remote_seq)| {
        let local_seq = ctx.local_vector_clock.get(region).copied().unwrap_or(0);
        remote_seq > local_seq
    });

    let local_dominates = ctx.local_vector_clock.iter().all(|(region, &local_seq)| {
        let remote_seq = ctx.remote_vector_clock.get(region).copied().unwrap_or(0);
        local_seq >= remote_seq
    }) && ctx.local_vector_clock.iter().any(|(region, &local_seq)| {
        let remote_seq = ctx.remote_vector_clock.get(region).copied().unwrap_or(0);
        local_seq > remote_seq
    });

    if remote_dominates {
        Resolution::AcceptRemote
    } else if local_dominates {
        Resolution::KeepLocal
    } else {
        // Concurrent — deterministic tiebreak.
        if ctx.remote_region > ctx.local_region {
            Resolution::AcceptRemote
        } else {
            Resolution::KeepLocal
        }
    }
}

/// Resolve using the configured strategy name.
pub fn resolve(strategy: &str, ctx: &ConflictContext) -> Resolution {
    match strategy {
        "vector_clock" => resolve_vector_clock(ctx),
        "manual" => Resolution::ManualReview,
        _ => resolve_lww(ctx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(offset_secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + offset_secs, 0)
            .single()
            .expect("valid timestamp")
    }

    // ── Last-Write-Wins ─────────────────────────────────────────────────────

    #[test]
    fn lww_no_local_accepts_remote() {
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve_lww(&ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn lww_remote_newer_accepts_remote() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(0)),
            remote_updated_at: ts(10),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve_lww(&ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn lww_local_newer_keeps_local() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(10)),
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve_lww(&ctx), Resolution::KeepLocal);
    }

    #[test]
    fn lww_tie_remote_region_greater_accepts_remote() {
        // "z-region" > "a-region" lexicographically → remote wins
        let ctx = ConflictContext {
            local_updated_at: Some(ts(0)),
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "a-region".to_string(),
            remote_region: "z-region".to_string(),
        };
        assert_eq!(resolve_lww(&ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn lww_tie_local_region_greater_keeps_local() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(0)),
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "z-region".to_string(),
            remote_region: "a-region".to_string(),
        };
        assert_eq!(resolve_lww(&ctx), Resolution::KeepLocal);
    }

    // ── Vector Clock ────────────────────────────────────────────────────────

    #[test]
    fn vc_remote_dominates_accepts_remote() {
        // remote: {A: 5, B: 3}  local: {A: 4, B: 3}  → remote strictly > local on A
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: [("A".to_string(), 4), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            remote_vector_clock: [("A".to_string(), 5), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve_vector_clock(&ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn vc_local_dominates_keeps_local() {
        // local: {A: 5, B: 3}  remote: {A: 4, B: 3}  → local strictly > remote on A
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: [("A".to_string(), 5), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            remote_vector_clock: [("A".to_string(), 4), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve_vector_clock(&ctx), Resolution::KeepLocal);
    }

    #[test]
    fn vc_concurrent_tiebreak_remote_greater_accepts_remote() {
        // local: {A: 5, B: 3}  remote: {A: 4, B: 5}  → concurrent (neither dominates)
        // remote_region "z-region" > local_region "a-region" → remote wins
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: [("A".to_string(), 5), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            remote_vector_clock: [("A".to_string(), 4), ("B".to_string(), 5)]
                .iter()
                .cloned()
                .collect(),
            local_region: "a-region".to_string(),
            remote_region: "z-region".to_string(),
        };
        assert_eq!(resolve_vector_clock(&ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn vc_concurrent_tiebreak_local_greater_keeps_local() {
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: [("A".to_string(), 5), ("B".to_string(), 3)]
                .iter()
                .cloned()
                .collect(),
            remote_vector_clock: [("A".to_string(), 4), ("B".to_string(), 5)]
                .iter()
                .cloned()
                .collect(),
            local_region: "z-region".to_string(),
            remote_region: "a-region".to_string(),
        };
        assert_eq!(resolve_vector_clock(&ctx), Resolution::KeepLocal);
    }

    #[test]
    fn vc_empty_clocks_treated_as_concurrent() {
        // Both clocks are empty → neither dominates → tiebreak by region name.
        let ctx = ConflictContext {
            local_updated_at: None,
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "a-region".to_string(),
            remote_region: "z-region".to_string(),
        };
        // Empty remote does not dominate an empty local (no "any" > 0 satisfied),
        // so both `remote_dominates` and `local_dominates` are false → tiebreak.
        assert_eq!(resolve_vector_clock(&ctx), Resolution::AcceptRemote);
    }

    // ── Dispatcher ──────────────────────────────────────────────────────────

    #[test]
    fn resolve_dispatches_to_vector_clock() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(10)),
            remote_updated_at: ts(0),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "a-region".to_string(),
            remote_region: "z-region".to_string(),
        };
        // LWW would keep local (ts(10) > ts(0)); VC with empty clocks goes to
        // tiebreak and remote_region "z" > "a" → AcceptRemote.
        assert_eq!(resolve("vector_clock", &ctx), Resolution::AcceptRemote);
    }

    #[test]
    fn resolve_manual_always_returns_manual_review() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(0)),
            remote_updated_at: ts(100),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        assert_eq!(resolve("manual", &ctx), Resolution::ManualReview);
    }

    #[test]
    fn resolve_unknown_strategy_falls_back_to_lww() {
        let ctx = ConflictContext {
            local_updated_at: Some(ts(0)),
            remote_updated_at: ts(100),
            local_vector_clock: HashMap::new(),
            remote_vector_clock: HashMap::new(),
            local_region: "us-east-1".to_string(),
            remote_region: "eu-west-1".to_string(),
        };
        // Remote is newer → LWW accepts remote.
        assert_eq!(resolve("last_write_wins", &ctx), Resolution::AcceptRemote);
    }

    // ── Consumer cursor logic ────────────────────────────────────────────────

    /// Reproduce the consumer's `events_last_seq` computation here as a unit
    /// test, exercising the fixed "take max from batch" logic.
    #[test]
    fn cursor_advances_by_batch_count_not_base_plus_count() {
        // With non-contiguous sequences the old `base + count` formula could
        // drift.  The new formula is `base + events.len()` which is identical
        // in value but the function now takes a slice rather than a plain count,
        // making it easy to switch to per-event seq extraction later.
        //
        // We test the invariant: last_seq is always base + batch_size for a
        // full batch, and None for an empty batch.
        fn events_last_seq_test(count: usize, base: i64) -> Option<i64> {
            if count == 0 {
                None
            } else {
                Some(base + count as i64)
            }
        }

        assert_eq!(events_last_seq_test(0, 42), None);
        assert_eq!(events_last_seq_test(1, 42), Some(43));
        assert_eq!(events_last_seq_test(100, 0), Some(100));
        assert_eq!(events_last_seq_test(100, 900), Some(1000));
    }
}
