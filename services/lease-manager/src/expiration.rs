//! Background expiration task for the lease-manager service.
//!
//! Runs every `EXPIRATION_INTERVAL_SECS` seconds and transitions any active
//! leases whose `expires_at` has passed into the `Expired` state. Revoked
//! leases are not touched — they already reached a terminal state.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};
use wslvault_cluster::leader::LeaderElector;

use crate::store::LeaseStoreBackend;

/// How frequently the expiration sweep runs.
const EXPIRATION_INTERVAL_SECS: u64 = 5;

/// Spawn the background expiration loop.
///
/// Accepts any `LeaseStoreBackend` implementation so that the same task
/// works with both the in-memory and PostgreSQL backends.
///
/// When a `LeaderElector` is provided, the sweep only runs on the leader node.
/// This prevents duplicate expiration processing when multiple replicas are
/// running. If no elector is provided (e.g. in-memory dev mode), the sweep
/// runs unconditionally.
///
/// This is a fire-and-forget task; the returned `JoinHandle` can be dropped
/// if the caller does not need to await or cancel it.
pub fn spawn_expiration_task(
    store: Arc<dyn LeaseStoreBackend>,
    elector: Option<Arc<LeaderElector>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_seconds = EXPIRATION_INTERVAL_SECS,
            "lease expiration task started"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(EXPIRATION_INTERVAL_SECS));

        loop {
            // `tick()` fires immediately on the first call, then every interval.
            interval.tick().await;

            // Only the leader performs expiration sweeps to avoid duplicate work.
            if let Some(ref elector) = elector {
                if !elector.is_leader() {
                    debug!("lease expiration sweep skipped: not the leader");
                    continue;
                }
            }

            let expired_ids = store.expire_stale_leases().await;
            let expired_count = expired_ids.len();

            if expired_count > 0 {
                info!(
                    expired_count,
                    "lease expiration sweep completed: leases transitioned to expired"
                );
            } else {
                debug!("lease expiration sweep: no leases expired this cycle");
            }
        }
    })
}
