//! Background health poller — checks all regions periodically.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};
use wslvault_cluster::leader::LeaderElector;
use wslvault_storage::pool::DbPool;

use crate::store;

const POLL_INTERVAL_SECS: u64 = 10;
const HEALTH_TIMEOUT_SECS: u64 = 5;
const OFFLINE_CONSECUTIVE_FAILURES: u32 = 3;

/// Run the region health polling loop. Only executes on the leader node.
pub async fn run_health_poller(pool: DbPool, elector: Arc<LeaderElector>, _local_region: &str) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HEALTH_TIMEOUT_SECS))
        .build()
        .expect("failed to build HTTP client");

    let mut failure_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();

    info!(
        interval_secs = POLL_INTERVAL_SECS,
        "region health poller started"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));

    loop {
        interval.tick().await;

        if !elector.is_leader() {
            debug!("region health poller: not the leader, skipping");
            continue;
        }

        let regions = match store::list_regions(&pool).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to list regions for health check");
                continue;
            }
        };

        for region in &regions {
            if region.is_local {
                // Always mark the local region as active.
                let _ = store::update_region_status(&pool, &region.id, "active", Some(0)).await;
                continue;
            }

            let health_url = format!("{}/health", region.endpoint);
            let start = std::time::Instant::now();

            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let rtt_ms = start.elapsed().as_millis() as i64;
                    failure_counts.insert(region.id.clone(), 0);
                    let _ = store::update_region_status(&pool, &region.id, "active", Some(rtt_ms))
                        .await;
                }
                Ok(resp) => {
                    warn!(
                        region = %region.id,
                        status = %resp.status(),
                        "region health check returned non-200"
                    );
                    let count = failure_counts.entry(region.id.clone()).or_insert(0);
                    *count += 1;
                    let status = if *count >= OFFLINE_CONSECUTIVE_FAILURES {
                        "offline"
                    } else {
                        "degraded"
                    };
                    let _ = store::update_region_status(&pool, &region.id, status, None).await;
                }
                Err(e) => {
                    warn!(
                        region = %region.id,
                        error = %e,
                        "region health check failed"
                    );
                    let count = failure_counts.entry(region.id.clone()).or_insert(0);
                    *count += 1;
                    let status = if *count >= OFFLINE_CONSECUTIVE_FAILURES {
                        "offline"
                    } else {
                        "degraded"
                    };
                    let _ = store::update_region_status(&pool, &region.id, status, None).await;
                }
            }
        }
    }
}
