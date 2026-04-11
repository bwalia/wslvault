//! Replication event producer — serves events to peer regions via HTTP API.

use axum::extract::{Query, State};
use axum::response::Json;
use serde::{Deserialize, Serialize};
use wslvault_storage::pool::DbPool;

use crate::consumer::ReplicationEvent;

#[derive(Deserialize)]
pub struct EventsQuery {
    /// The requesting region's ID (so we exclude their own events).
    pub source_region: Option<String>,
    /// Only return events created after this sequence number.
    pub after_seq: Option<i64>,
    /// Maximum number of events to return.
    pub limit: Option<i64>,
}

/// Serve pending replication events for a peer region.
///
/// `GET /v1/replication/events?source_region=X&after_seq=N&limit=100`
pub async fn get_events_handler(
    State(pool): State<DbPool>,
    Query(params): Query<EventsQuery>,
) -> Json<Vec<ReplicationEvent>> {
    let limit = params.limit.unwrap_or(100).min(1000);
    let after_seq = params.after_seq.unwrap_or(0);

    // Fetch events that were NOT originated by the requesting region
    // (a region should not replicate its own events back to itself).
    let events: Vec<ReplicationEvent> = match params.source_region {
        Some(ref requesting_region) => {
            sqlx::query_as::<_, (uuid::Uuid, String, String, serde_json::Value, serde_json::Value, chrono::DateTime<chrono::Utc>)>(
                r#"
                SELECT id, event_type, source_region, payload, vector_clock, created_at
                FROM system.replication_events
                WHERE source_region != $1
                  AND created_at > (
                      SELECT COALESCE(
                          (SELECT created_at FROM system.replication_events
                           ORDER BY created_at OFFSET $2 LIMIT 1),
                          '1970-01-01'::timestamptz
                      )
                  )
                ORDER BY created_at ASC
                LIMIT $3
                "#,
            )
            .bind(requesting_region)
            .bind(after_seq)
            .bind(limit)
            .fetch_all(pool.inner())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(id, event_type, source_region, payload, vector_clock, created_at)| {
                ReplicationEvent { id, event_type, source_region, payload, vector_clock, created_at }
            })
            .collect()
        }
        None => Vec::new(),
    };

    Json(events)
}

#[derive(Deserialize)]
pub struct AckRequest {
    pub region_id: String,
    pub last_sequence: i64,
}

#[derive(Serialize)]
pub struct AckResponse {
    pub acknowledged: bool,
}

/// Acknowledge that a peer has processed events up to a given sequence.
///
/// `POST /v1/replication/ack`
pub async fn ack_handler(
    State(pool): State<DbPool>,
    Json(req): Json<AckRequest>,
) -> Json<AckResponse> {
    let result = sqlx::query(
        r#"
        INSERT INTO system.region_sequences (region_id, sequence, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (region_id) DO UPDATE SET
            sequence = GREATEST(system.region_sequences.sequence, EXCLUDED.sequence),
            updated_at = now()
        "#,
    )
    .bind(&req.region_id)
    .bind(req.last_sequence)
    .execute(pool.inner())
    .await;

    Json(AckResponse {
        acknowledged: result.is_ok(),
    })
}
