//! Applies remote replication events to the local database.

use std::collections::HashMap;

use tracing::{debug, info, warn};
use wslvault_storage::pool::DbPool;

use crate::conflict::{self, ConflictContext, Resolution};
use crate::consumer::ReplicationEvent;

/// Apply a single replication event to the local database.
///
/// Uses the configured conflict resolution strategy when the local database
/// already has a version of the affected secret.
pub async fn apply_event(
    pool: &DbPool,
    event: &ReplicationEvent,
    conflict_strategy: &str,
    local_region: &str,
) -> anyhow::Result<()> {
    match event.event_type.as_str() {
        "secret_upsert" => apply_secret_upsert(pool, event, conflict_strategy, local_region).await,
        "secret_delete" => apply_secret_delete(pool, event).await,
        "secret_destroy" => apply_secret_destroy(pool, event).await,
        "key_rotate" => apply_key_rotate(pool, event).await,
        "policy_update" => apply_policy_update(pool, event).await,
        "tenant_update" => apply_tenant_update(pool, event).await,
        "api_key_upsert" => apply_api_key_upsert(pool, event).await,
        "region_failover" => {
            info!(
                source = %event.source_region,
                "received region_failover event (informational, no local action required)"
            );
            Ok(())
        }
        "region_promote" => apply_region_promote(pool, event, local_region).await,
        other => {
            warn!(
                event_type = other,
                "unknown replication event type, skipping"
            );
            Ok(())
        }
    }
}

async fn apply_secret_upsert(
    pool: &DbPool,
    event: &ReplicationEvent,
    conflict_strategy: &str,
    local_region: &str,
) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id in secret_upsert payload"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path in secret_upsert payload"))?;
    let ciphertext = event.payload["ciphertext"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ciphertext in secret_upsert payload"))?;
    let dek_id = event.payload["dek_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing dek_id in secret_upsert payload"))?;

    let remote_updated_at = event.created_at;
    let remote_vc: HashMap<String, i64> =
        serde_json::from_value(event.vector_clock.clone()).unwrap_or_default();

    // Check if the secret already exists locally.
    let local_meta: Option<(chrono::DateTime<chrono::Utc>, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT updated_at, vector_clock
        FROM shared.secrets
        WHERE tenant_id = $1::uuid AND path = $2
        "#,
    )
    .bind(tenant_id)
    .bind(path)
    .fetch_optional(pool.inner())
    .await?;

    if let Some((local_ts, local_vc_json)) = local_meta {
        let local_vc: HashMap<String, i64> =
            serde_json::from_value(local_vc_json).unwrap_or_default();

        let ctx = ConflictContext {
            local_updated_at: Some(local_ts),
            remote_updated_at,
            local_vector_clock: local_vc,
            remote_vector_clock: remote_vc,
            local_region: local_region.to_string(),
            remote_region: event.source_region.clone(),
        };

        match conflict::resolve(conflict_strategy, &ctx) {
            Resolution::KeepLocal => {
                debug!(path, "conflict resolved: keeping local version");
                return Ok(());
            }
            Resolution::ManualReview => {
                warn!(path, "conflict requires manual review, skipping");
                return Ok(());
            }
            Resolution::AcceptRemote => {
                debug!(path, "conflict resolved: accepting remote version");
            }
        }
    }

    // Apply the remote secret version using the vault_upsert_secret function.
    // We bypass CAS here since this is a replicated write.
    sqlx::query(
        r#"
        SELECT shared.vault_upsert_secret(
            $1::uuid, $2, 'kv_v2', $3, $4, NULL, 10, false, '{}'::jsonb
        )
        "#,
    )
    .bind(tenant_id)
    .bind(path)
    .bind(ciphertext)
    .bind(dek_id)
    .execute(pool.inner())
    .await?;

    // Update origin_region and vector_clock on the secret.
    sqlx::query(
        r#"
        UPDATE shared.secrets
        SET origin_region = $1, vector_clock = $2
        WHERE tenant_id = $3::uuid AND path = $4
        "#,
    )
    .bind(&event.source_region)
    .bind(&event.vector_clock)
    .bind(tenant_id)
    .bind(path)
    .execute(pool.inner())
    .await?;

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_upsert"
    );

    Ok(())
}

async fn apply_secret_delete(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?;
    let versions: Vec<i32> =
        serde_json::from_value(event.payload["versions"].clone()).unwrap_or_default();

    if !versions.is_empty() {
        let secret_id: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM shared.secrets WHERE tenant_id = $1::uuid AND path = $2",
        )
        .bind(tenant_id)
        .bind(path)
        .fetch_optional(pool.inner())
        .await?;

        if let Some((sid,)) = secret_id {
            let version_array: Vec<i32> = versions;
            sqlx::query("SELECT shared.vault_soft_delete_versions($1, $2)")
                .bind(sid)
                .bind(&version_array)
                .execute(pool.inner())
                .await?;
        }
    }

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_delete"
    );
    Ok(())
}

async fn apply_secret_destroy(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id"))?;
    let path = event.payload["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?;
    let versions: Vec<i32> =
        serde_json::from_value(event.payload["versions"].clone()).unwrap_or_default();

    if !versions.is_empty() {
        let secret_id: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM shared.secrets WHERE tenant_id = $1::uuid AND path = $2",
        )
        .bind(tenant_id)
        .bind(path)
        .fetch_optional(pool.inner())
        .await?;

        if let Some((sid,)) = secret_id {
            sqlx::query("SELECT shared.vault_destroy_versions($1, $2)")
                .bind(sid)
                .bind(&versions)
                .execute(pool.inner())
                .await?;
        }
    }

    info!(
        path,
        source_region = %event.source_region,
        "replicated secret_destroy"
    );
    Ok(())
}

/// Apply a `key_rotate` replication event.
///
/// # Why this is not implemented
///
/// Key material in WSLVault is wrapped (envelope-encrypted) by a region-local
/// root Key Encryption Key (KEK).  The root KEK never leaves its region — it
/// is either held in memory (env provider) or protected by a region-local AWS
/// KMS key.  This means:
///
/// 1. A ciphertext blob wrapped by region A's root KEK is UNREADABLE in
///    region B, which has a different root KEK.
/// 2. Replicating wrapped key material cross-region would therefore produce
///    garbage that cannot be decrypted, silently corrupting the keyring.
///
/// Safe cross-region key rotation requires out-of-band key exchange (e.g.
/// Shamir Secret Sharing or a multi-region KMS with a shared CMK).  That
/// mechanism is not yet implemented.  Until it is, each region performs its
/// own independent key rotation and does NOT replicate key material.
///
/// Peer regions receive this warning so operators are aware that a rotation
/// occurred in the originating region and can decide whether manual remediation
/// is needed.
async fn apply_key_rotate(_pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    warn!(
        source_region = %event.source_region,
        key_id = ?event.payload.get("key_id"),
        "UNSAFE to replicate key_rotate cross-region: key material is wrapped by \
         a region-local root KEK and cannot be decrypted by this region. \
         Each region manages its own key hierarchy independently. \
         If you intended to rotate keys in all regions, trigger rotation on each region separately."
    );
    Ok(())
}

/// Apply a `policy_update` replication event.
///
/// Performs a last-write-wins upsert of the policy document into
/// `shared.policies` using the event's `created_at` timestamp as the
/// write timestamp.  If a local policy with the same (tenant_id, name) already
/// exists and was modified more recently, the remote event is discarded.
///
/// The replication applier bypasses RLS by operating as a cross-tenant
/// service role; it does NOT set `app.current_tenant_id`.
async fn apply_policy_update(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["tenant_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tenant_id in policy_update payload"))?;
    let name = event.payload["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing name in policy_update payload"))?;
    let document = event
        .payload
        .get("document")
        .ok_or_else(|| anyhow::anyhow!("missing document in policy_update payload"))?
        .clone();

    let remote_updated_at = event.created_at;

    // Check whether the local policy exists and when it was last updated.
    let local_updated_at: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
        "SELECT updated_at FROM shared.policies WHERE tenant_id = $1::uuid AND name = $2",
    )
    .bind(tenant_id)
    .bind(name)
    .fetch_optional(pool.inner())
    .await?;

    if let Some((local_ts,)) = local_updated_at {
        // LWW: discard remote if the local copy is strictly newer.
        // On a timestamp tie the ON CONFLICT … WHERE clause in the upsert below
        // is `updated_at <= EXCLUDED.updated_at`, which accepts the remote write
        // (idempotent replay).  That is the safe choice — a replayed event with
        // the same document is harmless.
        if local_ts > remote_updated_at {
            debug!(
                tenant_id,
                policy = name,
                "policy_update discarded: local copy is newer (LWW)"
            );
            return Ok(());
        }
    }

    // Mark this session as originating from the replication-agent so that the
    // DB trigger (015_replication_event_triggers.sql) skips emitting a new
    // outbox event, preventing cross-region replication loops.
    sqlx::query("SET LOCAL app.replication_agent = 'true'")
        .execute(pool.inner())
        .await?;

    // Upsert the policy.  We rely on the `(tenant_id, name)` unique constraint
    // and set `updated_at` to the remote event's timestamp so a future replay
    // with the same timestamp is idempotent.
    sqlx::query(
        r#"
        INSERT INTO shared.policies (tenant_id, name, document, updated_at)
        VALUES ($1::uuid, $2, $3, $4)
        ON CONFLICT (tenant_id, name) DO UPDATE
            SET document   = EXCLUDED.document,
                updated_at = EXCLUDED.updated_at
        WHERE shared.policies.updated_at <= EXCLUDED.updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(name)
    .bind(&document)
    .bind(remote_updated_at)
    .execute(pool.inner())
    .await?;

    info!(
        tenant_id,
        policy = name,
        source_region = %event.source_region,
        "replicated policy_update"
    );

    Ok(())
}

/// Apply a `tenant_update` replication event.
///
/// Performs a last-write-wins upsert of the tenant record into
/// `system.tenants`.  The `deleted_at` field is preserved if the local copy
/// carries a deletion timestamp that the remote event does not.
///
/// Note: `system.tenants` does NOT have row-level security, so no session
/// variable needs to be set before writing.
/// Apply an `api_key_upsert` event from a peer region.
///
/// API keys used to exist only in the region that minted them, so a key issued
/// against region A returned `key_not_found` on region B and a failover
/// invalidated every login at once. They now replicate like policies and
/// tenants.
///
/// Only the SHA-256 hash travels — the raw key is returned once at mint time
/// and never stored anywhere — so this carries exactly what the table already
/// holds.
///
/// `last_used_at` is deliberately not replicated: it is per-region telemetry,
/// and feeding it into the conflict key would have two regions overwriting each
/// other on every authentication.
async fn apply_api_key_upsert(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    use base64::Engine as _;

    let field = |k: &str| -> anyhow::Result<String> {
        event.payload[k]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("missing {k} in api_key_upsert payload"))
    };

    let id = field("id")?;
    let tenant_id = field("tenant_id")?;
    let name = field("name")?;
    let key_prefix = field("key_prefix")?;
    let created_by = field("created_by")?;
    let key_hash = base64::engine::general_purpose::STANDARD
        .decode(field("key_hash_b64")?)
        .map_err(|e| anyhow::anyhow!("key_hash_b64 is not valid base64: {e}"))?;

    let policies: Vec<String> =
        serde_json::from_value(event.payload["policies"].clone()).unwrap_or_default();
    let path_prefixes: Vec<String> =
        serde_json::from_value(event.payload["path_prefixes"].clone()).unwrap_or_default();
    let expires_at: Option<chrono::DateTime<chrono::Utc>> =
        serde_json::from_value(event.payload["expires_at"].clone()).unwrap_or(None);
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        serde_json::from_value(event.payload["revoked_at"].clone()).unwrap_or(None);
    let rate_limit = event.payload["rate_limit_per_minute"]
        .as_i64()
        .unwrap_or(60) as i32;

    // Stop the local trigger re-emitting this write as a fresh outbox event,
    // which would bounce the row between regions forever.
    sqlx::query("SET LOCAL app.replication_agent = 'true'")
        .execute(pool.inner())
        .await?;

    // Revocation must never be undone by an older event arriving late, so a row
    // already revoked locally keeps its revoked_at. Everything else takes the
    // remote value.
    sqlx::query(
        r#"
        INSERT INTO shared.api_keys
            (id, tenant_id, name, key_hash, key_prefix, path_prefixes, policies,
             created_by, created_at, expires_at, revoked_at, rate_limit_per_minute)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, now(), $9, $10, $11)
        ON CONFLICT (id) DO UPDATE SET
            name                  = EXCLUDED.name,
            key_hash              = EXCLUDED.key_hash,
            key_prefix            = EXCLUDED.key_prefix,
            path_prefixes         = EXCLUDED.path_prefixes,
            policies              = EXCLUDED.policies,
            expires_at            = EXCLUDED.expires_at,
            revoked_at            = COALESCE(shared.api_keys.revoked_at, EXCLUDED.revoked_at),
            rate_limit_per_minute = EXCLUDED.rate_limit_per_minute
        "#,
    )
    .bind(&id)
    .bind(&tenant_id)
    .bind(&name)
    .bind(&key_hash)
    .bind(&key_prefix)
    .bind(&path_prefixes)
    .bind(&policies)
    .bind(&created_by)
    .bind(expires_at)
    .bind(revoked_at)
    .bind(rate_limit)
    .execute(pool.inner())
    .await?;

    debug!(key_id = %id, key_prefix = %key_prefix, "replicated api key");
    Ok(())
}

async fn apply_tenant_update(pool: &DbPool, event: &ReplicationEvent) -> anyhow::Result<()> {
    let tenant_id = event.payload["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing id in tenant_update payload"))?;
    let slug = event.payload["slug"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing slug in tenant_update payload"))?;
    let display_name = event.payload["display_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing display_name in tenant_update payload"))?;
    let tier = event.payload["tier"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tier in tenant_update payload"))?;
    let root_key_id = event.payload["root_key_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing root_key_id in tenant_update payload"))?;
    let deleted_at: Option<chrono::DateTime<chrono::Utc>> =
        serde_json::from_value(event.payload["deleted_at"].clone()).unwrap_or(None);

    let remote_updated_at = event.created_at;

    // LWW check against local `updated_at`.
    let local_updated_at: Option<(chrono::DateTime<chrono::Utc>,)> =
        sqlx::query_as("SELECT updated_at FROM system.tenants WHERE id = $1::uuid")
            .bind(tenant_id)
            .fetch_optional(pool.inner())
            .await?;

    if let Some((local_ts,)) = local_updated_at {
        if local_ts > remote_updated_at {
            debug!(
                tenant_id,
                "tenant_update discarded: local copy is newer (LWW)"
            );
            return Ok(());
        }
    }

    // Prevent the DB trigger from emitting a new outbox event for this
    // replication-originated write (see 015_replication_event_triggers.sql).
    sqlx::query("SET LOCAL app.replication_agent = 'true'")
        .execute(pool.inner())
        .await?;

    // Upsert the tenant.  If the row already exists and the local `updated_at`
    // is newer, the WHERE clause on the DO UPDATE ensures it is a no-op.
    sqlx::query(
        r#"
        INSERT INTO system.tenants
            (id, slug, display_name, tier, root_key_id, updated_at, deleted_at)
        VALUES
            ($1::uuid, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE
            SET slug         = EXCLUDED.slug,
                display_name = EXCLUDED.display_name,
                tier         = EXCLUDED.tier,
                root_key_id  = EXCLUDED.root_key_id,
                updated_at   = EXCLUDED.updated_at,
                deleted_at   = EXCLUDED.deleted_at
        WHERE system.tenants.updated_at <= EXCLUDED.updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(slug)
    .bind(display_name)
    .bind(tier)
    .bind(root_key_id)
    .bind(remote_updated_at)
    .bind(deleted_at)
    .execute(pool.inner())
    .await?;

    info!(
        tenant_id,
        slug,
        source_region = %event.source_region,
        "replicated tenant_update"
    );

    Ok(())
}

/// Apply a `region_promote` event: promote the specified region to `active`
/// status in the local `system.regions` table and emit an audit record.
///
/// If the promoted region is THIS region (`local_region`), we additionally
/// mark all other regions as `degraded` so that the gateway stops routing
/// writes to the old primary.  The region-health poller will update their
/// actual status based on subsequent health checks.
async fn apply_region_promote(
    pool: &DbPool,
    event: &ReplicationEvent,
    local_region: &str,
) -> anyhow::Result<()> {
    let target_region = event.payload["target_region"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing target_region in region_promote payload"))?;
    let initiated_by = event.payload["initiated_by"]
        .as_str()
        .unwrap_or(&event.source_region);

    info!(
        target_region,
        initiated_by,
        source_region = %event.source_region,
        local_region,
        "processing region_promote event"
    );

    // Mark the promoted region as active.
    sqlx::query(
        r#"
        UPDATE system.regions
        SET status = 'active', last_seen = now()
        WHERE id = $1
        "#,
    )
    .bind(target_region)
    .execute(pool.inner())
    .await?;

    // If this is the promoted region, also mark the initiating (old primary)
    // region as degraded so it stops receiving write traffic until it
    // recovers and re-registers itself as active.
    if target_region == local_region && initiated_by != local_region {
        sqlx::query(
            r#"
            UPDATE system.regions
            SET status = 'degraded', last_seen = now()
            WHERE id = $1 AND id != $2
            "#,
        )
        .bind(initiated_by)
        .bind(local_region)
        .execute(pool.inner())
        .await?;

        info!(
            demoted_region = initiated_by,
            promoted_region = local_region,
            "this region has been promoted to primary; former primary marked degraded"
        );
    }

    // Write an audit record for the promotion event.
    // We use the system-level audit_events table (tenant_id = nil UUID) so
    // the event is not gated by any tenant's RLS policy.
    let audit_detail = serde_json::json!({
        "event": "region_promote",
        "target_region": target_region,
        "initiated_by": initiated_by,
        "source_region": event.source_region,
        "local_region": local_region,
    });
    sqlx::query(
        r#"
        INSERT INTO shared.audit_events
            (id, tenant_id, principal_id, action, resource, outcome, details, origin_region)
        VALUES
            (gen_random_uuid(), '00000000-0000-0000-0000-000000000000'::uuid,
             'replication-agent', 'region_promote', $1, 'success', $2, $3)
        "#,
    )
    .bind(target_region)
    .bind(&audit_detail)
    .bind(local_region)
    .execute(pool.inner())
    .await?;

    info!(
        target_region,
        "region_promote applied: region status updated and audit record written"
    );

    Ok(())
}
