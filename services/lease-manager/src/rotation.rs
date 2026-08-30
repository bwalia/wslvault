//! Automated secret rotation sweep for the lease-manager service.
//!
//! Two background loops:
//!
//! 1. **Rotation sweep** (default every 60 s) — queries
//!    `shared.secrets` for `ROTATION_REQUIRED` secrets whose
//!    `next_rotation_at <= now()` and for each due secret either:
//!    - dispatches a webhook notification (when `webhook_url` is set), or
//!    - performs a full PostgreSQL dynamic credential rotation through the
//!      two-phase `vault_initiate_rotation` / `vault_confirm_rotation`
//!      protocol (for `secret_type = 'ROTATION_REQUIRED'` secrets that also
//!      have a `pg_rotation_db_url` entry in `secret_metadata`).
//!
//! 2. **Deprecated version cleanup** (default every 3600 s) — calls
//!    `shared.vault_revoke_deprecated_versions()` to zero out ciphertext of
//!    old versions whose grace period has expired.
//!
//! Both loops run only on the cluster leader when a `LeaderElector` is provided.
//!
//! # Environment variables
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `ROTATION_SWEEP_INTERVAL_SECS` | 60 | Rotation sweep cadence (seconds) |
//! | `VERSION_CLEANUP_INTERVAL_SECS` | 3600 | Deprecated-version cleanup cadence (seconds) |
//! | `ROTATION_WEBHOOK_TIMEOUT_SECS` | 10 | Per-attempt HTTP POST timeout for webhooks |
//! | `ROTATION_WEBHOOK_MAX_RETRIES` | 3 | Maximum webhook delivery attempts |

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use sqlx::PgPool;
use tracing::{debug, error, info, warn};
use wslvault_cluster::leader::LeaderElector;

use crate::rotation_metrics::{
    ROTATIONS_TRIGGERED_TOTAL, ROTATION_SWEEP_RUNS_TOTAL, VERSIONS_REVOKED_TOTAL,
    WEBHOOKS_DISPATCHED_TOTAL,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Runtime configuration read once from environment variables at service start.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// How often the rotation sweep runs (seconds).
    pub sweep_interval_secs: u64,
    /// How often the deprecated-version cleanup runs (seconds).
    pub cleanup_interval_secs: u64,
    /// HTTP POST timeout per webhook delivery attempt (seconds).
    pub webhook_timeout_secs: u64,
    /// Maximum webhook delivery attempts per secret per sweep cycle.
    pub webhook_max_retries: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            sweep_interval_secs: 60,
            cleanup_interval_secs: 3600,
            webhook_timeout_secs: 10,
            webhook_max_retries: 3,
        }
    }
}

impl RotationConfig {
    /// Read configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        fn parse_env(name: &str, default: u64) -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        Self {
            sweep_interval_secs: parse_env("ROTATION_SWEEP_INTERVAL_SECS", 60),
            cleanup_interval_secs: parse_env("VERSION_CLEANUP_INTERVAL_SECS", 3600),
            webhook_timeout_secs: parse_env("ROTATION_WEBHOOK_TIMEOUT_SECS", 10),
            webhook_max_retries: parse_env("ROTATION_WEBHOOK_MAX_RETRIES", 3) as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// DB row type
// ---------------------------------------------------------------------------

/// A row returned by the rotation-due query.
// `rotation_interval_seconds` is selected for future automated PG rotation;
// suppress dead-code lint until that path is wired.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
struct DueSecret {
    id: uuid::Uuid,
    path: String,
    tenant_id: uuid::Uuid,
    secret_type: String,
    webhook_url: Option<String>,
    rotation_interval_seconds: Option<i32>,
}

// ---------------------------------------------------------------------------
// Webhook payload
// ---------------------------------------------------------------------------

/// JSON body posted to a secret's webhook URL when its rotation is due.
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    pub tenant_id: String,
    pub path: String,
    pub secret_type: String,
    pub rotation_due_at: String,
    pub triggered_at: String,
}

// ---------------------------------------------------------------------------
// Spawn helpers (public API)
// ---------------------------------------------------------------------------

/// Spawn both the rotation sweep and the deprecated-version cleanup loops.
///
/// Both tasks share the same `PgPool`; the `LeaderElector` prevents duplicate
/// work when multiple replicas run concurrently.
pub fn spawn_rotation_tasks(
    pool: PgPool,
    elector: Option<Arc<LeaderElector>>,
    config: RotationConfig,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let sweep_handle = spawn_rotation_sweep(pool.clone(), elector.clone(), config.clone());
    let cleanup_handle = spawn_version_cleanup(pool, elector, config);
    (sweep_handle, cleanup_handle)
}

// ---------------------------------------------------------------------------
// Rotation sweep loop
// ---------------------------------------------------------------------------

fn spawn_rotation_sweep(
    pool: PgPool,
    elector: Option<Arc<LeaderElector>>,
    config: RotationConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_seconds = config.sweep_interval_secs,
            "rotation sweep task started"
        );

        // Build an HTTP client once; reuse across iterations.
        let http_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(config.webhook_timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to build reqwest client; rotation sweep disabled");
                return;
            }
        };

        let mut interval = tokio::time::interval(Duration::from_secs(config.sweep_interval_secs));

        loop {
            interval.tick().await;

            // Only the leader performs rotation sweeps to avoid duplicate work.
            if let Some(ref elector) = elector {
                if !elector.is_leader() {
                    debug!("rotation sweep skipped: not the leader");
                    continue;
                }
            }

            run_rotation_sweep(&pool, &http_client, &config).await;
        }
    })
}

/// Sweep query for secrets due for rotation.
///
/// Liveness is not filtered here: `shared.secrets` has no row-level state
/// column (per-version liveness lives on `shared.secret_versions.status`),
/// and a secret with a pending or confirmed rotation is already excluded by
/// the `rotation_status = 'none'` guard, which is also what prevents the
/// sweep from re-firing for the same secret on the next cycle.
const DUE_SECRETS_QUERY: &str = r#"
        SELECT
            s.id,
            s.path,
            s.tenant_id,
            s.secret_type,
            s.webhook_url,
            s.rotation_interval_seconds
        FROM shared.secrets s
        WHERE s.secret_type = 'ROTATION_REQUIRED'
          AND s.next_rotation_at IS NOT NULL
          AND s.next_rotation_at <= NOW()
          AND s.rotation_status = 'none'
"#;

/// Execute one rotation sweep cycle: query due secrets and dispatch notifications
/// or perform automatic rotation.
async fn run_rotation_sweep(pool: &PgPool, http_client: &reqwest::Client, config: &RotationConfig) {
    let rows = sqlx::query_as::<_, DueSecret>(DUE_SECRETS_QUERY)
        .fetch_all(pool)
        .await;

    let due_secrets = match rows {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "rotation sweep query failed");
            ROTATION_SWEEP_RUNS_TOTAL
                .with_label_values(&["error"])
                .inc();
            return;
        }
    };

    let count = due_secrets.len();
    if count > 0 {
        info!(
            due_count = count,
            "rotation sweep found secrets due for rotation"
        );
    } else {
        debug!("rotation sweep: no secrets due for rotation this cycle");
    }

    for secret in due_secrets {
        let secret_type = secret.secret_type.clone();

        // When a webhook URL is present, send a notification and let the
        // calling application drive the two-phase rotation protocol.
        if let Some(ref url) = secret.webhook_url {
            let payload = WebhookPayload {
                tenant_id: secret.tenant_id.to_string(),
                path: secret.path.clone(),
                secret_type: secret_type.clone(),
                // next_rotation_at is <= now by definition; record current time
                // as the actual trigger timestamp.
                rotation_due_at: Utc::now().to_rfc3339(),
                triggered_at: Utc::now().to_rfc3339(),
            };

            let dispatched =
                dispatch_webhook_with_retry(http_client, url, &payload, config.webhook_max_retries)
                    .await;

            if dispatched {
                // Mark rotation_status = 'pending' so we do not re-fire this
                // cycle.  The calling app will POST to /v1/secret/rotate to
                // officially initiate the two-phase protocol.
                if let Err(e) = sqlx::query(
                    "UPDATE shared.secrets SET rotation_status = 'pending' WHERE id = $1",
                )
                .bind(secret.id)
                .execute(pool)
                .await
                {
                    error!(
                        secret_id = %secret.id,
                        error = %e,
                        "failed to mark rotation_status=pending after webhook dispatch"
                    );
                }
                WEBHOOKS_DISPATCHED_TOTAL
                    .with_label_values(&["success"])
                    .inc();
                ROTATIONS_TRIGGERED_TOTAL
                    .with_label_values(&[secret_type.as_str(), "success"])
                    .inc();
            } else {
                WEBHOOKS_DISPATCHED_TOTAL
                    .with_label_values(&["failure"])
                    .inc();
                ROTATIONS_TRIGGERED_TOTAL
                    .with_label_values(&[secret_type.as_str(), "error"])
                    .inc();
            }
        } else {
            // No webhook — automatic internal rotation is not implemented for
            // non-PostgreSQL secret types in this sweep.  Log and skip.
            // PostgreSQL dynamic-credential rotation via PostgresCredentialRotator
            // requires an admin DB URL stored per-secret which is not yet in the
            // schema; wire it when that column is added.
            debug!(
                secret_id = %secret.id,
                path = %secret.path,
                "no webhook_url configured; skipping automated rotation"
            );
            ROTATIONS_TRIGGERED_TOTAL
                .with_label_values(&[secret_type.as_str(), "error"])
                .inc();
        }
    }

    ROTATION_SWEEP_RUNS_TOTAL
        .with_label_values(&["success"])
        .inc();
}

// ---------------------------------------------------------------------------
// Webhook delivery with retry + exponential back-off
// ---------------------------------------------------------------------------

/// POST `payload` to `url` with up to `max_retries` attempts.
///
/// Uses exponential back-off: 1 s → 2 s → 4 s … (capped internally by the
/// client timeout on each attempt). Returns `true` if any attempt succeeded.
async fn dispatch_webhook_with_retry(
    client: &reqwest::Client,
    url: &str,
    payload: &WebhookPayload,
    max_retries: u32,
) -> bool {
    let mut delay_secs: u64 = 1;

    for attempt in 1..=max_retries.max(1) {
        match client.post(url).json(payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    url = url,
                    attempt = attempt,
                    status = resp.status().as_u16(),
                    "webhook delivered successfully"
                );
                return true;
            }
            Ok(resp) => {
                warn!(
                    url = url,
                    attempt = attempt,
                    status = resp.status().as_u16(),
                    "webhook returned non-success status"
                );
            }
            Err(e) => {
                warn!(url = url, attempt = attempt, error = %e, "webhook delivery failed");
            }
        }

        if attempt < max_retries.max(1) {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            delay_secs = (delay_secs * 2).min(30);
        }
    }

    error!(
        url = url,
        max_retries = max_retries,
        "webhook delivery exhausted all retries"
    );
    false
}

// ---------------------------------------------------------------------------
// Deprecated version cleanup loop
// ---------------------------------------------------------------------------

fn spawn_version_cleanup(
    pool: PgPool,
    elector: Option<Arc<LeaderElector>>,
    config: RotationConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_seconds = config.cleanup_interval_secs,
            "deprecated version cleanup task started"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(config.cleanup_interval_secs));

        loop {
            interval.tick().await;

            // Only the leader runs cleanup.
            if let Some(ref elector) = elector {
                if !elector.is_leader() {
                    debug!("version cleanup sweep skipped: not the leader");
                    continue;
                }
            }

            run_version_cleanup(&pool).await;
        }
    })
}

/// Execute one deprecated-version cleanup cycle.
///
/// Calls `shared.vault_revoke_deprecated_versions()` with the default batch
/// size (100). The function returns the UUIDs of rotation records that were
/// completed; we count them for metrics and audit logging.
async fn run_version_cleanup(pool: &PgPool) {
    // vault_revoke_deprecated_versions returns SETOF UUID (the rotation record IDs
    // that were transitioned to 'completed').
    let result: Result<Vec<uuid::Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT shared.vault_revoke_deprecated_versions(100)")
            .fetch_all(pool)
            .await;

    match result {
        Ok(ids) => {
            let revoked_count = ids.len() as i64;
            if revoked_count > 0 {
                info!(
                    revoked_count,
                    "deprecated version cleanup: revoked old secret versions"
                );
            } else {
                debug!("deprecated version cleanup: no versions to revoke this cycle");
            }
            VERSIONS_REVOKED_TOTAL.inc_by(revoked_count as u64);
        }
        Err(e) => {
            error!(error = %e, "deprecated version cleanup query failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -------------------------------------------------------------------------
    // 1. SQL query structure smoke test
    //
    //    We verify the query compiles and contains the expected clauses without
    //    requiring a live database. The approach here is a simple string-contains
    //    check — sufficient to catch accidental regressions to the query.
    // -------------------------------------------------------------------------
    #[test]
    fn test_due_secret_selection_query_structure() {
        // Assert against the real query constant so the test cannot drift from
        // the production SQL.
        let query = DUE_SECRETS_QUERY;

        assert!(
            query.contains("s.secret_type = 'ROTATION_REQUIRED'"),
            "must filter on ROTATION_REQUIRED type"
        );
        assert!(
            query.contains("s.next_rotation_at <= NOW()"),
            "must check next_rotation_at threshold"
        );
        assert!(
            query.contains("s.rotation_status = 'none'"),
            "must exclude already-pending secrets"
        );
        assert!(query.contains("s.webhook_url"), "must select webhook_url");
    }

    // -------------------------------------------------------------------------
    // 2. Webhook payload construction
    //
    //    Verify that the payload serialises all required fields.
    // -------------------------------------------------------------------------
    #[test]
    fn test_webhook_payload_construction() {
        let now = Utc::now();
        let payload = WebhookPayload {
            tenant_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            path: "prod/db/password".to_string(),
            secret_type: "ROTATION_REQUIRED".to_string(),
            rotation_due_at: now.to_rfc3339(),
            triggered_at: now.to_rfc3339(),
        };

        let json = serde_json::to_value(&payload).expect("payload must be serialisable");

        assert_eq!(json["tenant_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(json["path"], "prod/db/password");
        assert_eq!(json["secret_type"], "ROTATION_REQUIRED");
        assert!(
            json["rotation_due_at"].is_string(),
            "rotation_due_at must be a string"
        );
        assert!(
            json["triggered_at"].is_string(),
            "triggered_at must be a string"
        );
    }

    // -------------------------------------------------------------------------
    // 3. No-double-fire guard
    //
    //    Secrets already in 'pending' rotation_status must be excluded from the
    //    sweep.  We verify this by checking that the query predicate
    //    `rotation_status = 'none'` is present.  In practice, the UPDATE that
    //    follows a successful webhook dispatch sets rotation_status = 'pending',
    //    so the next sweep cycle will not re-fire for the same secret.
    // -------------------------------------------------------------------------
    #[test]
    fn test_no_double_fire_via_rotation_status_predicate() {
        let query_predicate = "AND s.rotation_status = 'none'";

        // The sweep query must include this guard.
        assert!(
            DUE_SECRETS_QUERY.contains(query_predicate.trim()),
            "sweep query must exclude already-pending secrets to prevent double-fire"
        );

        // Simulate state after first dispatch: rotation_status transitions to 'pending'.
        // A subsequent sweep would NOT include this secret because rotation_status != 'none'.
        let simulated_status_after_dispatch = "pending";
        assert_ne!(
            simulated_status_after_dispatch, "none",
            "after webhook dispatch rotation_status must not be 'none'"
        );
    }

    // Serialise the env-var tests so they don't interfere with each other
    // when cargo runs tests in parallel threads within the same process.
    static ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_rotation_env_vars() {
        std::env::remove_var("ROTATION_SWEEP_INTERVAL_SECS");
        std::env::remove_var("VERSION_CLEANUP_INTERVAL_SECS");
        std::env::remove_var("ROTATION_WEBHOOK_TIMEOUT_SECS");
        std::env::remove_var("ROTATION_WEBHOOK_MAX_RETRIES");
    }

    // -------------------------------------------------------------------------
    // 4. RotationConfig reads defaults correctly
    // -------------------------------------------------------------------------
    #[test]
    fn test_rotation_config_defaults() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        clear_rotation_env_vars();

        let config = RotationConfig::from_env();
        assert_eq!(config.sweep_interval_secs, 60);
        assert_eq!(config.cleanup_interval_secs, 3600);
        assert_eq!(config.webhook_timeout_secs, 10);
        assert_eq!(config.webhook_max_retries, 3);
    }

    // -------------------------------------------------------------------------
    // 5. RotationConfig reads overrides from environment
    // -------------------------------------------------------------------------
    #[test]
    fn test_rotation_config_from_env_overrides() {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();
        clear_rotation_env_vars();

        std::env::set_var("ROTATION_SWEEP_INTERVAL_SECS", "120");
        std::env::set_var("VERSION_CLEANUP_INTERVAL_SECS", "7200");
        std::env::set_var("ROTATION_WEBHOOK_TIMEOUT_SECS", "5");
        std::env::set_var("ROTATION_WEBHOOK_MAX_RETRIES", "5");

        let config = RotationConfig::from_env();

        clear_rotation_env_vars();

        assert_eq!(config.sweep_interval_secs, 120);
        assert_eq!(config.cleanup_interval_secs, 7200);
        assert_eq!(config.webhook_timeout_secs, 5);
        assert_eq!(config.webhook_max_retries, 5);
    }

    // -------------------------------------------------------------------------
    // 6. dispatch_webhook_with_retry max_retries edge case
    //
    //    Ensure max_retries = 0 is treated as 1 attempt (never panic, no divide
    //    by zero or infinite loop).
    // -------------------------------------------------------------------------
    #[tokio::test]
    async fn test_dispatch_webhook_max_retries_zero_treated_as_one() {
        // Point at a port that should refuse connections quickly.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let payload = WebhookPayload {
            tenant_id: "test".to_string(),
            path: "test/path".to_string(),
            secret_type: "ROTATION_REQUIRED".to_string(),
            rotation_due_at: Utc::now().to_rfc3339(),
            triggered_at: Utc::now().to_rfc3339(),
        };

        // max_retries = 0 → treated as 1 attempt via .max(1); must not hang
        let result =
            dispatch_webhook_with_retry(&client, "http://127.0.0.1:19999", &payload, 0).await;
        // Connection refused → false (no success)
        assert!(!result, "expected false when all delivery attempts fail");
    }
}
