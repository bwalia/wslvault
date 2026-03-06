//! Background expiration task for the lease-manager service.
//!
//! Runs every `EXPIRATION_INTERVAL_SECS` seconds and transitions any active
//! leases whose `expires_at` has passed into the `Expired` state. Revoked
//! leases are not touched — they already reached a terminal state.

use std::time::Duration;

use tracing::{debug, info};

use crate::store::{expire_stale_leases, SharedLeaseStore};

/// How frequently the expiration sweep runs.
const EXPIRATION_INTERVAL_SECS: u64 = 5;

/// Spawn the background expiration loop.
///
/// This is a fire-and-forget task; the returned `JoinHandle` can be dropped
/// if the caller does not need to await or cancel it.
pub fn spawn_expiration_task(store: SharedLeaseStore) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_seconds = EXPIRATION_INTERVAL_SECS,
            "lease expiration task started"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(EXPIRATION_INTERVAL_SECS));

        loop {
            // `tick()` fires immediately on the first call, then every interval.
            interval.tick().await;

            let expired_count = expire_stale_leases(&store).await;

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
