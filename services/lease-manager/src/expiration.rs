//! Background expiration task for the lease-manager service.
//!
//! Runs every `EXPIRATION_INTERVAL_SECS` seconds and transitions any active
//! leases whose `expires_at` has passed into the `Expired` state. Revoked
//! leases are not touched — they already reached a terminal state.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};
use wslvault_cluster::leader::LeaderElector;

use crate::identity_client::IdentityClient;
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
    identity: Option<IdentityClient>,
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

            let due = store.list_stale_active_leases().await;
            let mut expired_count = 0usize;

            for record in due {
                if let Some((hash, principal_id, expires_at)) = record.token_revocation() {
                    match &identity {
                        Some(client) => {
                            if let Err(e) = client
                                .revoke_token_by_hash(
                                    &hash,
                                    &record.tenant_id,
                                    &principal_id,
                                    expires_at,
                                )
                                .await
                            {
                                error!(
                                    lease_id = %record.id,
                                    error = %e,
                                    "token lease expire: identity unreachable; leaving lease active for retry"
                                );
                                continue;
                            }
                        }
                        None => {
                            error!(
                                lease_id = %record.id,
                                "token lease expired with IDENTITY_SERVICE_GRPC unset; JWT stays live until exp"
                            );
                        }
                    }
                }

                if let Err(e) = store.mark_expired(&record.id).await {
                    error!(lease_id = %record.id, error = %e, "failed to mark lease expired");
                    continue;
                }
                expired_count += 1;
            }

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
