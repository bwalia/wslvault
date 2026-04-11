//! Audit event persistence operations against the shared.audit_events table.
//!
//! The audit_events table is append-only and partitioned by `timestamp`.
//! Queries use parameterised filters to avoid SQL injection and to let
//! Postgres push predicates into the correct partition.
//!
//! The `tenant_id` column in the database is a `UUID`; callers pass it as
//! a `&str` (the string representation) so that the audit-service proto layer
//! does not need to parse UUIDs before calling into this module.

use sqlx::Row;
use uuid::Uuid;

use crate::pool::DbPool;
use wslvault_core::VaultError;

/// A single audit event as stored in – and retrieved from – the database.
#[derive(Debug, Clone)]
pub struct StoredAuditEvent {
    pub id: Uuid,
    /// Tenant UUID represented as a string for compatibility with the
    /// audit-service proto layer which carries tenant IDs as plain strings.
    pub tenant_id: String,
    pub principal_id: String,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub outcome_detail: String,
    pub details: serde_json::Value,
    /// Client IP address serialised to a string.  The underlying column is
    /// `INET`; we convert via `::text` in SQL to avoid requiring the pgcrypto
    /// INET codec in the application layer.
    pub client_ip: String,
    pub signature: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Append a single audit event to the append-only `shared.audit_events` table.
///
/// `tenant_id` must be a valid UUID string – it is parsed before binding to
/// match the `UUID NOT NULL` column type in the database.
pub async fn insert_event(pool: &DbPool, event: &StoredAuditEvent) -> Result<(), VaultError> {
    // Parse the string tenant_id into a Uuid so we bind the correct Postgres
    // type.  The audit-service is responsible for providing a well-formed UUID.
    let tenant_uuid = Uuid::parse_str(&event.tenant_id).map_err(|e| {
        VaultError::ValidationError {
            field: "tenant_id".into(),
            reason: format!("invalid UUID: {}", e),
        }
    })?;

    sqlx::query(
        "INSERT INTO shared.audit_events
             (id, tenant_id, principal_id, action, resource, outcome,
              outcome_detail, details, client_ip, signature, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11)",
    )
    .bind(event.id)
    .bind(tenant_uuid)
    .bind(&event.principal_id)
    .bind(&event.action)
    .bind(&event.resource)
    .bind(&event.outcome)
    .bind(&event.outcome_detail)
    .bind(&event.details)
    .bind(&event.client_ip)
    .bind(&event.signature)
    .bind(event.timestamp)
    .execute(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Query audit events with optional filters, returning a page of results and
/// the total count of matching rows.
///
/// All filter parameters are optional; when `None` is supplied for a filter
/// the corresponding predicate is omitted (i.e. no restriction is applied for
/// that field).
///
/// # Parameters
/// - `tenant_id`        – restrict to events for a specific tenant UUID string.
/// - `start_time`       – include only events at or after this timestamp.
/// - `end_time`         – include only events before or at this timestamp.
/// - `action_filter`    – restrict to events whose `action` equals this value.
/// - `principal_filter` – restrict to events whose `principal_id` equals this.
/// - `limit`            – maximum number of rows to return (page size).
/// - `offset`           – number of rows to skip before returning results.
///
/// Returns `(events, total_count)` where `total_count` is the number of
/// matching rows without the limit/offset applied (useful for pagination).
pub async fn query_events(
    pool: &DbPool,
    tenant_id: Option<&str>,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
    action_filter: Option<&str>,
    principal_filter: Option<&str>,
    limit: i32,
    offset: i32,
) -> Result<(Vec<StoredAuditEvent>, i64), VaultError> {
    // Parse the optional tenant UUID string once so we can reuse it for both
    // the count query and the data query without repeating the parse.
    let tenant_uuid: Option<Uuid> = tenant_id
        .map(|s| {
            Uuid::parse_str(s).map_err(|e| VaultError::ValidationError {
                field: "tenant_id".into(),
                reason: format!("invalid UUID: {}", e),
            })
        })
        .transpose()?;

    // Fetch the total count of matching rows for pagination metadata.
    let count_row = sqlx::query(
        "SELECT COUNT(*) AS total
         FROM shared.audit_events
         WHERE ($1::uuid  IS NULL OR tenant_id    = $1)
           AND ($2::timestamptz IS NULL OR timestamp    >= $2)
           AND ($3::timestamptz IS NULL OR timestamp    <= $3)
           AND ($4::text  IS NULL OR action        = $4)
           AND ($5::text  IS NULL OR principal_id  = $5)",
    )
    .bind(tenant_uuid)
    .bind(start_time)
    .bind(end_time)
    .bind(action_filter)
    .bind(principal_filter)
    .fetch_one(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    let total: i64 = count_row.get("total");

    // Fetch the requested page of events.  We cast the INET column to text so
    // we can retrieve it as a plain String without needing a custom Postgres
    // type codec.
    let rows = sqlx::query(
        "SELECT id, tenant_id, principal_id, action, resource, outcome,
                COALESCE(outcome_detail, '') AS outcome_detail,
                details, COALESCE(client_ip::text, '') AS client_ip,
                COALESCE(signature, '') AS signature, timestamp
         FROM shared.audit_events
         WHERE ($1::uuid  IS NULL OR tenant_id    = $1)
           AND ($2::timestamptz IS NULL OR timestamp    >= $2)
           AND ($3::timestamptz IS NULL OR timestamp    <= $3)
           AND ($4::text  IS NULL OR action        = $4)
           AND ($5::text  IS NULL OR principal_id  = $5)
         ORDER BY timestamp DESC
         LIMIT $6 OFFSET $7",
    )
    .bind(tenant_uuid)
    .bind(start_time)
    .bind(end_time)
    .bind(action_filter)
    .bind(principal_filter)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| VaultError::Database {
        reason: e.to_string(),
    })?;

    let events = rows
        .into_iter()
        .map(|row| StoredAuditEvent {
            id: row.get::<Uuid, _>("id"),
            // Convert the UUID back to a string for the caller.
            tenant_id: row.get::<Uuid, _>("tenant_id").to_string(),
            principal_id: row.get("principal_id"),
            action: row.get("action"),
            resource: row.get("resource"),
            outcome: row.get("outcome"),
            outcome_detail: row.get("outcome_detail"),
            details: row.get("details"),
            client_ip: row.get("client_ip"),
            signature: row.get("signature"),
            timestamp: row.get("timestamp"),
        })
        .collect();

    Ok((events, total))
}
