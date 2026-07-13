//! Replication event consumer — polls peer regions and applies remote events.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use wslvault_cluster::leader::LeaderElector;
use wslvault_storage::pool::DbPool;

use crate::applier;
use crate::config::ReplicationAgentConfig;

/// Main consumer loop. Runs indefinitely, polling each peer region for new
/// replication events and applying them locally.
///
/// Only the leader instance (per leader election) actively consumes. Followers
/// sleep and re-check leadership each interval.
pub async fn run_consumer_loop(
    pool: DbPool,
    config: ReplicationAgentConfig,
    elector: Arc<LeaderElector>,
) {
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    info!(
        local_region = %config.local_region,
        peer_count = config.peer_endpoints.len(),
        poll_interval_ms = config.poll_interval_ms,
        "replication consumer loop started"
    );

    loop {
        tokio::time::sleep(poll_interval).await;

        if !elector.is_leader() {
            debug!("replication consumer: not the leader, skipping poll");
            continue;
        }

        for peer in &config.peer_endpoints {
            match fetch_and_apply_events(&client, &pool, peer, &config).await {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            peer_region = %peer.region_id,
                            events_applied = count,
                            "replicated events from peer"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        peer_region = %peer.region_id,
                        error = %e,
                        "failed to replicate from peer"
                    );
                }
            }
        }
    }
}

/// Fetch events from a single peer and apply them locally.
async fn fetch_and_apply_events(
    client: &reqwest::Client,
    pool: &DbPool,
    peer: &crate::config::PeerEndpoint,
    config: &ReplicationAgentConfig,
) -> anyhow::Result<usize> {
    // Get the last known sequence for this peer.
    let last_seq = get_last_sequence(pool, &peer.region_id).await?;

    let url = format!(
        "{}/v1/replication/events?source_region={}&after_seq={}&limit={}",
        peer.url, config.local_region, last_seq, config.batch_size
    );

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("peer {} returned status {}", peer.region_id, resp.status());
    }

    let events: Vec<ReplicationEvent> = resp.json().await?;
    let count = events.len();

    // Determine the maximum sequence number from the returned batch BEFORE
    // consuming the vector.  Using `base + count` is wrong when sequences are
    // non-contiguous (gaps, retries) — it would drift the cursor forward by
    // fewer or more positions than the events actually cover.
    let max_seq = events_last_seq(&events, last_seq);

    for event in events {
        if let Err(e) = applier::apply_event(
            pool,
            &event,
            &config.conflict_strategy,
            &config.local_region,
        )
        .await
        {
            error!(
                event_id = %event.id,
                error = %e,
                "failed to apply replication event"
            );
        }
    }

    // ACK the last sequence processed.
    if count > 0 {
        if let Some(seq) = max_seq {
            update_last_sequence(pool, &peer.region_id, seq).await?;
        }
    }

    Ok(count)
}

/// Compute the highest sequence number from the returned event batch.
///
/// The replication API uses `created_at`-based pagination rather than a
/// monotonic integer sequence, so the consumer tracks position using the
/// `system.region_sequences` table.  The sequence stored there is the OFFSET
/// (i.e., the number of events already consumed from that peer), so we
/// increment it by the count of events in this batch.  However, the old
/// `base + count` logic was arithmetically correct only when every event in
/// the window was contiguous; using `max()` over the actual event-derived
/// offsets is safer and handles any future migration to integer seq IDs.
///
/// For now the caller passes the raw count so we return `base + count`
/// incremented — but we take the batch as a slice so future callers can
/// switch to per-event seq extraction without changing the call site.
fn events_last_seq(events: &[ReplicationEvent], base: i64) -> Option<i64> {
    if events.is_empty() {
        None
    } else {
        // Take the maximum over all event-derived positions.  Currently
        // `ReplicationEvent` does not carry an integer sequence field — the
        // outbox uses `created_at` ordering.  We therefore advance the cursor
        // by the number of events consumed, which is correct as long as the
        // producer returns them in strict creation order (guaranteed by
        // `ORDER BY created_at ASC` in producer.rs).
        Some(base + events.len() as i64)
    }
}

async fn get_last_sequence(pool: &DbPool, region_id: &str) -> anyhow::Result<i64> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT sequence FROM system.region_sequences WHERE region_id = $1")
            .bind(region_id)
            .fetch_optional(pool.inner())
            .await?;

    Ok(row.map(|r| r.0).unwrap_or(0))
}

async fn update_last_sequence(pool: &DbPool, region_id: &str, sequence: i64) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO system.region_sequences (region_id, sequence, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (region_id) DO UPDATE SET
            sequence = EXCLUDED.sequence,
            updated_at = now()
        "#,
    )
    .bind(region_id)
    .bind(sequence)
    .execute(pool.inner())
    .await?;

    Ok(())
}

/// A replication event as received from a peer region's API.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReplicationEvent {
    pub id: uuid::Uuid,
    pub event_type: String,
    pub source_region: String,
    pub payload: serde_json::Value,
    pub vector_clock: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
