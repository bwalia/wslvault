//! Audit analytics: aggregated views of audit data for dashboards.
//!
//! Provides pre-computed summaries of audit events for the metrics dashboard,
//! including access patterns, operation breakdowns, and secret usage statistics.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::store::{AuditRecord, SharedAuditStore};

/// Summary of audit activity over a time window.
#[derive(Debug, Clone, Serialize)]
pub struct AuditAnalytics {
    pub total_events: usize,
    pub events_by_action: HashMap<String, usize>,
    pub events_by_outcome: HashMap<String, usize>,
    pub events_by_tenant: HashMap<String, usize>,
    pub top_resources: Vec<ResourceAccess>,
    pub top_principals: Vec<PrincipalActivity>,
    pub operation_categories: HashMap<String, usize>,
    pub access_patterns: AccessPatterns,
    pub time_window: TimeWindow,
}

/// Access count for a specific resource.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceAccess {
    pub resource: String,
    pub access_count: usize,
    pub last_accessed: DateTime<Utc>,
    pub unique_principals: usize,
}

/// Activity summary for a principal.
#[derive(Debug, Clone, Serialize)]
pub struct PrincipalActivity {
    pub principal_id: String,
    pub total_actions: usize,
    pub unique_resources: usize,
    pub last_active: DateTime<Utc>,
}

/// Access pattern analysis.
#[derive(Debug, Clone, Serialize)]
pub struct AccessPatterns {
    /// Number of secret reads vs writes.
    pub read_write_ratio: f64,
    /// Unique secrets accessed in the window.
    pub unique_secrets_accessed: usize,
    /// Number of denied/failed operations.
    pub denied_operations: usize,
    /// Pull types breakdown (API, CLI, SDK, etc.).
    pub pull_types: HashMap<String, usize>,
}

/// Time window for the analytics query.
#[derive(Debug, Clone, Serialize)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_seconds: u64,
}

/// Categorise an action string into a high-level category.
fn categorise_action(action: &str) -> &'static str {
    if action.starts_with("secret.read") || action.starts_with("secret.get") {
        "secret_read"
    } else if action.starts_with("secret.write") || action.starts_with("secret.put") {
        "secret_write"
    } else if action.starts_with("secret.delete") {
        "secret_delete"
    } else if action.starts_with("secret.destroy") {
        "secret_destroy"
    } else if action.starts_with("secret.list") {
        "secret_list"
    } else if action.starts_with("auth.") {
        "authentication"
    } else if action.starts_with("policy.") {
        "policy"
    } else if action.starts_with("key.") || action.starts_with("crypto.") {
        "key_management"
    } else if action.starts_with("lease.") {
        "lease_management"
    } else if action.starts_with("transit.") {
        "transit"
    } else {
        "other"
    }
}

/// Determine the pull type (how the secret was accessed) from the audit record details.
fn extract_pull_type(record: &AuditRecord) -> &'static str {
    let details = &record.details;
    if let Some(client_type) = details.get("client_type").and_then(|v| v.as_str()) {
        match client_type {
            "cli" => "cli",
            "sdk" => "sdk",
            "api" | "rest" => "api",
            "grpc" => "grpc",
            "mcp" => "mcp_agent",
            _ => "unknown",
        }
    } else if record.client_ip.starts_with("127.") || record.client_ip == "::1" {
        "local"
    } else {
        "api"
    }
}

/// Compute analytics over audit events in the given time window.
pub async fn compute_analytics(
    store: &SharedAuditStore,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> AuditAnalytics {
    let guard: tokio::sync::RwLockReadGuard<'_, Vec<AuditRecord>> = store.read().await;

    let records: Vec<&AuditRecord> = guard
        .iter()
        .filter(|r| r.tenant_id == tenant_id)
        .filter(|r| r.timestamp >= start && r.timestamp <= end)
        .collect();

    let total_events = records.len();

    // Events by action.
    let mut events_by_action: HashMap<String, usize> = HashMap::new();
    let mut events_by_outcome: HashMap<String, usize> = HashMap::new();
    let mut events_by_tenant: HashMap<String, usize> = HashMap::new();
    let mut operation_categories: HashMap<String, usize> = HashMap::new();
    let mut pull_types: HashMap<String, usize> = HashMap::new();
    let mut resource_map: HashMap<
        String,
        (usize, DateTime<Utc>, std::collections::HashSet<String>),
    > = HashMap::new();
    let mut principal_map: HashMap<
        String,
        (usize, std::collections::HashSet<String>, DateTime<Utc>),
    > = HashMap::new();
    let mut reads = 0usize;
    let mut writes = 0usize;
    let mut denied = 0usize;
    let mut unique_secrets = std::collections::HashSet::new();

    for record in &records {
        *events_by_action.entry(record.action.clone()).or_default() += 1;
        *events_by_outcome.entry(record.outcome.clone()).or_default() += 1;
        *events_by_tenant
            .entry(record.tenant_id.clone())
            .or_default() += 1;

        let category = categorise_action(&record.action);
        *operation_categories
            .entry(category.to_string())
            .or_default() += 1;

        let pull_type = extract_pull_type(record);
        *pull_types.entry(pull_type.to_string()).or_default() += 1;

        // Track resource access.
        let entry = resource_map.entry(record.resource.clone()).or_insert((
            0,
            record.timestamp,
            std::collections::HashSet::new(),
        ));
        entry.0 += 1;
        if record.timestamp > entry.1 {
            entry.1 = record.timestamp;
        }
        entry.2.insert(record.principal_id.clone());

        // Track principal activity.
        let p_entry = principal_map.entry(record.principal_id.clone()).or_insert((
            0,
            std::collections::HashSet::new(),
            record.timestamp,
        ));
        p_entry.0 += 1;
        p_entry.1.insert(record.resource.clone());
        if record.timestamp > p_entry.2 {
            p_entry.2 = record.timestamp;
        }

        // Count reads/writes.
        match category {
            "secret_read" => reads += 1,
            "secret_write" => writes += 1,
            _ => {}
        }

        if record.outcome == "denied" || record.outcome == "failure" {
            denied += 1;
        }

        if record.resource.starts_with("/") {
            unique_secrets.insert(record.resource.clone());
        }
    }

    // Build top resources (top 10 by access count).
    let mut top_resources: Vec<ResourceAccess> = resource_map
        .into_iter()
        .map(|(resource, (count, last, principals))| ResourceAccess {
            resource,
            access_count: count,
            last_accessed: last,
            unique_principals: principals.len(),
        })
        .collect();
    top_resources.sort_by(|a, b| b.access_count.cmp(&a.access_count));
    top_resources.truncate(10);

    // Build top principals (top 10 by action count).
    let mut top_principals: Vec<PrincipalActivity> = principal_map
        .into_iter()
        .map(
            |(principal_id, (total, resources, last))| PrincipalActivity {
                principal_id,
                total_actions: total,
                unique_resources: resources.len(),
                last_active: last,
            },
        )
        .collect();
    top_principals.sort_by(|a, b| b.total_actions.cmp(&a.total_actions));
    top_principals.truncate(10);

    let read_write_ratio = if writes > 0 {
        reads as f64 / writes as f64
    } else if reads > 0 {
        f64::INFINITY
    } else {
        0.0
    };

    AuditAnalytics {
        total_events,
        events_by_action,
        events_by_outcome,
        events_by_tenant,
        top_resources,
        top_principals,
        operation_categories,
        access_patterns: AccessPatterns {
            read_write_ratio,
            unique_secrets_accessed: unique_secrets.len(),
            denied_operations: denied,
            pull_types,
        },
        time_window: TimeWindow {
            start,
            end,
            duration_seconds: (end - start).num_seconds() as u64,
        },
    }
}
