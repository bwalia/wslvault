//! Cron-based scheduler loop for sync jobs.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use wslvault_cluster::leader::LeaderElector;
use wslvault_storage::pool::DbPool;

use crate::runner;
use crate::store;

const SCHEDULER_POLL_INTERVAL_SECS: u64 = 30;

/// Main scheduler loop. Polls for enabled scheduled jobs and runs them
/// when their cron schedule matches the current time.
///
/// Only the leader replica runs jobs (via LeaderElector).
pub async fn run_scheduler_loop(pool: DbPool, elector: Arc<LeaderElector>) {
    info!("sync scheduler loop started");

    let mut interval = tokio::time::interval(Duration::from_secs(SCHEDULER_POLL_INTERVAL_SECS));

    loop {
        interval.tick().await;

        if !elector.is_leader() {
            debug!("sync scheduler: not the leader, skipping cycle");
            continue;
        }

        let jobs = match store::get_enabled_scheduled_jobs(&pool).await {
            Ok(jobs) => jobs,
            Err(e) => {
                warn!(error = %e, "failed to load sync jobs");
                continue;
            }
        };

        for job in jobs {
            // Check if this job should run now based on its cron schedule.
            if !should_run_now(&job) {
                continue;
            }

            info!(
                integration = %job.integration_id,
                connector = %job.connector_type,
                "executing scheduled sync job"
            );

            match runner::run_sync_job(&pool, &job).await {
                Ok(result) => {
                    let status = if result.failed > 0 {
                        "partial"
                    } else {
                        "success"
                    };
                    let _ = store::update_job_result(
                        &pool,
                        job.id,
                        status,
                        serde_json::to_value(&result).unwrap_or_default(),
                        0,
                    )
                    .await;
                    info!(
                        integration = %job.integration_id,
                        synced = result.synced,
                        failed = result.failed,
                        "sync job completed"
                    );
                }
                Err(e) => {
                    let failures = job.consecutive_failures + 1;
                    let _ = store::update_job_result(
                        &pool,
                        job.id,
                        "failed",
                        serde_json::json!({"error": e.to_string()}),
                        failures,
                    )
                    .await;
                    error!(
                        integration = %job.integration_id,
                        consecutive_failures = failures,
                        error = %e,
                        "sync job failed"
                    );
                }
            }
        }
    }
}

/// Check if a job should run now based on its cron schedule and last_run_at.
fn should_run_now(job: &store::SyncJob) -> bool {
    let schedule_str = match &job.schedule {
        Some(s) => s,
        None => return false,
    };

    let schedule = match cron::Schedule::from_str(schedule_str) {
        Ok(s) => s,
        Err(_) => {
            warn!(
                integration = %job.integration_id,
                schedule = schedule_str,
                "invalid cron schedule"
            );
            return false;
        }
    };

    use std::str::FromStr;
    let now = chrono::Utc::now();

    // Find the most recent scheduled time.
    let next_after = job
        .last_run_at
        .unwrap_or_else(|| now - chrono::Duration::hours(24));

    // If any scheduled time between last_run and now exists, it's time to run.
    schedule
        .after(&next_after)
        .take(1)
        .any(|scheduled| scheduled <= now)
}
