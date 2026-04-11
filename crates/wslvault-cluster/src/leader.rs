//! Leader election via PostgreSQL advisory locks.
//!
//! Each service instance calls `LeaderElector::run()` which spawns a background
//! loop that attempts to acquire a PostgreSQL advisory lock. Only one connection
//! can hold a given advisory lock at a time; if the holder disconnects (crash,
//! restart) the lock is automatically released by PostgreSQL.
//!
//! The lock key is derived by hashing the service name to a stable `i64`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};
use wslvault_storage::pool::DbPool;

use crate::config::ClusterConfig;
use crate::error::ClusterError;
use crate::node::NodeId;
use crate::store;

/// Leader elector backed by PostgreSQL advisory locks.
///
/// Create one per service instance. Call `run()` to start the background
/// election loop, then query `is_leader()` from any task that should only
/// execute on the leader node.
#[derive(Clone)]
pub struct LeaderElector {
    pool: DbPool,
    lock_key: i64,
    service_name: String,
    node_id: NodeId,
    region: String,
    heartbeat_interval: Duration,
    is_leader: Arc<AtomicBool>,
}

impl LeaderElector {
    /// Create a new leader elector for the given service.
    ///
    /// The `lock_key` is derived from a hash of `service_name` so each service
    /// type competes independently for leadership.
    pub fn new(pool: DbPool, config: &ClusterConfig, service_name: &str) -> Self {
        let lock_key = Self::hash_service_name(service_name);
        let node_id = NodeId(config.resolved_node_id());

        info!(
            service = service_name,
            node_id = %node_id,
            lock_key,
            "leader elector initialised"
        );

        Self {
            pool,
            lock_key,
            service_name: service_name.to_string(),
            node_id,
            region: config.region.clone(),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_secs),
            is_leader: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` if this node currently holds the leadership lock.
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// Returns the node identifier.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Spawn the background election loop.
    ///
    /// The loop runs indefinitely:
    /// 1. Attempts to acquire the advisory lock (non-blocking).
    /// 2. If acquired, updates the cluster_nodes table and sets `is_leader = true`.
    /// 3. Sleeps for `heartbeat_interval` and refreshes the heartbeat.
    /// 4. If lock acquisition fails, sets `is_leader = false` and retries.
    pub fn run(&self) -> tokio::task::JoinHandle<()> {
        let elector = self.clone();

        tokio::spawn(async move {
            // Register this node in the cluster_nodes table.
            if let Err(e) = store::register_node(
                &elector.pool,
                &elector.service_name,
                &elector.node_id,
                &elector.region,
            )
            .await
            {
                warn!(error = %e, "failed to register cluster node; continuing with election");
            }

            let mut was_leader = false;

            loop {
                match elector.try_acquire_lock().await {
                    Ok(true) => {
                        if !was_leader {
                            info!(
                                service = %elector.service_name,
                                node_id = %elector.node_id,
                                "acquired leadership"
                            );
                            was_leader = true;
                        }
                        elector.is_leader.store(true, Ordering::Relaxed);

                        // Update heartbeat and leader flag in cluster_nodes.
                        if let Err(e) = store::update_heartbeat(
                            &elector.pool,
                            &elector.node_id,
                            true,
                        )
                        .await
                        {
                            warn!(error = %e, "failed to update leader heartbeat");
                        }
                    }
                    Ok(false) => {
                        if was_leader {
                            info!(
                                service = %elector.service_name,
                                node_id = %elector.node_id,
                                "lost leadership"
                            );
                            was_leader = false;
                        }
                        elector.is_leader.store(false, Ordering::Relaxed);

                        // Update heartbeat as follower.
                        if let Err(e) = store::update_heartbeat(
                            &elector.pool,
                            &elector.node_id,
                            false,
                        )
                        .await
                        {
                            debug!(error = %e, "failed to update follower heartbeat");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "leader election attempt failed");
                        elector.is_leader.store(false, Ordering::Relaxed);
                    }
                }

                tokio::time::sleep(elector.heartbeat_interval).await;
            }
        })
    }

    /// Attempt to acquire the PostgreSQL advisory lock (non-blocking).
    ///
    /// `pg_try_advisory_lock` returns `true` if the lock was acquired, `false`
    /// if another session holds it. It does NOT block.
    async fn try_acquire_lock(&self) -> Result<bool, ClusterError> {
        let row: (bool,) =
            sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(self.lock_key)
                .fetch_one(self.pool.inner())
                .await
                .map_err(|e| ClusterError::LockAcquisitionFailed {
                    reason: e.to_string(),
                })?;

        Ok(row.0)
    }

    /// Derive a stable i64 lock key from the service name.
    fn hash_service_name(name: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish() as i64
    }
}
