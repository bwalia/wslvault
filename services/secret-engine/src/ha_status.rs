//! HA status HTTP endpoint for the secret-engine service.
//!
//! Exposes `/v1/sys/ha-status` which returns the full cluster health report
//! including node states, region health, replication status, and failover history.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use wslvault_core::ha::cluster::{ClusterSummary, SharedClusterState};
use wslvault_core::ha::health::HaStatus;

/// Response body for the HA status endpoint when HA is disabled.
#[derive(Debug, Serialize)]
pub struct HaStatusResponse {
    pub ha_enabled: bool,
    pub status: String,
    pub cluster: Option<ClusterSummary>,
    pub is_leader: bool,
    pub leader_node: Option<String>,
    pub timestamp: String,
}

/// Handler for GET /v1/sys/ha-status when HA is disabled (standalone mode).
pub async fn ha_status_standalone() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HaStatusResponse {
            ha_enabled: false,
            status: format!("{:?}", HaStatus::Standalone),
            cluster: None,
            is_leader: true,
            leader_node: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }),
    )
}

/// Handler for GET /v1/sys/ha-status when HA is enabled.
///
/// This handler is registered when HA mode is configured. It reads the
/// shared cluster state and builds a comprehensive health report.
pub async fn ha_status_enabled(
    cluster_state: Arc<SharedClusterState>,
) -> impl IntoResponse {
    let state = cluster_state.read().await;
    let summary = state.cluster_summary();

    let is_leader = state.current_leader.as_ref() == Some(&state.local_node_id);

    (
        StatusCode::OK,
        Json(HaStatusResponse {
            ha_enabled: true,
            status: if is_leader { "leader".into() } else { "standby".into() },
            cluster: Some(summary),
            is_leader,
            leader_node: state.current_leader.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }),
    )
}
