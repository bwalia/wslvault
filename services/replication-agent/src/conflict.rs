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
