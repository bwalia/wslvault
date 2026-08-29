-- WSLVault Tenant Quotas
-- Tracks per-tenant resource limits and current usage.
-- Quota records are auto-created when a tenant is registered, and
-- secret counts are kept in sync via triggers on shared.secrets.
--
-- Apply after 011_scim_persistence.sql.

-- =============================================================================
-- 1. Tenant quotas table
-- =============================================================================

CREATE TABLE IF NOT EXISTS shared.tenant_quotas (
    tenant_id                 UUID PRIMARY KEY REFERENCES system.tenants(id) ON DELETE CASCADE,
    -- Secret limits
    max_secrets               INTEGER NOT NULL DEFAULT 10000,
    max_secret_versions       INTEGER NOT NULL DEFAULT 100,
    max_secret_size_bytes     INTEGER NOT NULL DEFAULT 65536,   -- 64 KB per secret value
    -- Transit key limits
    max_transit_keys          INTEGER NOT NULL DEFAULT 100,
    -- Rate limits (requests per second)
    read_rate_limit           INTEGER NOT NULL DEFAULT 1000,
    write_rate_limit          INTEGER NOT NULL DEFAULT 200,
    -- Storage
    max_storage_bytes         BIGINT  NOT NULL DEFAULT 1073741824,  -- 1 GB
    current_storage_bytes     BIGINT  NOT NULL DEFAULT 0,
    -- Live counts (maintained by triggers)
    current_secret_count      INTEGER NOT NULL DEFAULT 0,
    current_transit_key_count INTEGER NOT NULL DEFAULT 0,
    -- Metadata
    tier                      TEXT    NOT NULL DEFAULT 'shared'
        CHECK (tier IN ('shared', 'dedicated', 'sovereign')),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE shared.tenant_quotas IS
    'Per-tenant resource limits and live usage counters. '
    'One row per tenant; auto-populated when a tenant is created.';

COMMENT ON COLUMN shared.tenant_quotas.max_secret_size_bytes IS
    'Maximum allowed byte length for a single secret value (plaintext).';
COMMENT ON COLUMN shared.tenant_quotas.read_rate_limit IS
    'Maximum read requests per second allowed for this tenant.';
COMMENT ON COLUMN shared.tenant_quotas.write_rate_limit IS
    'Maximum write/delete requests per second allowed for this tenant.';
COMMENT ON COLUMN shared.tenant_quotas.current_storage_bytes IS
    'Running total of compressed ciphertext bytes across all secret versions.';

-- =============================================================================
-- 2. Index: look up quotas by tier for bulk operations (e.g. tier upgrades)
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_tenant_quotas_tier
    ON shared.tenant_quotas (tier);

-- =============================================================================
-- 3. updated_at trigger (same pattern as scim tables)
-- =============================================================================

CREATE OR REPLACE FUNCTION shared.tenant_quotas_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenant_quotas_updated_at ON shared.tenant_quotas;
CREATE TRIGGER trg_tenant_quotas_updated_at
    BEFORE UPDATE ON shared.tenant_quotas
    FOR EACH ROW EXECUTE FUNCTION shared.tenant_quotas_set_updated_at();

-- =============================================================================
-- 4. Auto-create quota record when a tenant is inserted into system.tenants
--
--    The new quota row inherits the tenant's tier so that default limits can
--    be adjusted later by updating the tier column.
-- =============================================================================

CREATE OR REPLACE FUNCTION shared.ensure_tenant_quota()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO shared.tenant_quotas (tenant_id, tier)
    VALUES (NEW.id, NEW.tier)
    ON CONFLICT (tenant_id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION shared.ensure_tenant_quota() IS
    'Automatically provisions a quota row for every new tenant. '
    'The tier is copied from system.tenants so that default limits '
    'can vary by service tier.';

DROP TRIGGER IF EXISTS trg_ensure_tenant_quota ON system.tenants;
CREATE TRIGGER trg_ensure_tenant_quota
    AFTER INSERT ON system.tenants
    FOR EACH ROW EXECUTE FUNCTION shared.ensure_tenant_quota();

-- =============================================================================
-- 5. Increment / decrement current_secret_count on shared.secrets changes
--
--    Uses a conditional UPDATE so one function body handles both INSERT
--    (TG_OP = 'INSERT', delta = +1) and DELETE (TG_OP = 'DELETE', delta = -1).
--    The count is clamped to 0 on decrement to guard against any
--    inconsistency that might otherwise push it negative.
-- =============================================================================

CREATE OR REPLACE FUNCTION shared.update_secret_count()
RETURNS TRIGGER AS $$
DECLARE
    v_tenant_id UUID;
    v_delta     INTEGER;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_tenant_id := NEW.tenant_id;
        v_delta     := 1;
    ELSIF TG_OP = 'DELETE' THEN
        v_tenant_id := OLD.tenant_id;
        v_delta     := -1;
    ELSE
        -- UPDATE on shared.secrets does not change the count
        RETURN NEW;
    END IF;

    UPDATE shared.tenant_quotas
    SET current_secret_count = GREATEST(0, current_secret_count + v_delta)
    WHERE tenant_id = v_tenant_id;

    -- If no quota row exists yet (e.g. during a data migration) create one
    -- silently so the trigger never blocks the DML.
    IF NOT FOUND AND v_delta = 1 THEN
        INSERT INTO shared.tenant_quotas (tenant_id)
        VALUES (v_tenant_id)
        ON CONFLICT (tenant_id) DO UPDATE
            SET current_secret_count = shared.tenant_quotas.current_secret_count + 1;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION shared.update_secret_count() IS
    'Keeps tenant_quotas.current_secret_count in sync with rows in shared.secrets. '
    'Triggered AFTER INSERT OR DELETE on shared.secrets.';

DROP TRIGGER IF EXISTS trg_secrets_quota_count ON shared.secrets;
CREATE TRIGGER trg_secrets_quota_count
    AFTER INSERT OR DELETE ON shared.secrets
    FOR EACH ROW EXECUTE FUNCTION shared.update_secret_count();

-- =============================================================================
-- 6. Back-fill quota rows for any tenants that existed before this migration
-- =============================================================================

INSERT INTO shared.tenant_quotas (tenant_id, tier)
SELECT id, tier
FROM system.tenants
WHERE deleted_at IS NULL
ON CONFLICT (tenant_id) DO NOTHING;

-- Synchronise current_secret_count from live data in the same pass.
UPDATE shared.tenant_quotas tq
SET current_secret_count = (
    SELECT COUNT(*)
    FROM shared.secrets s
    WHERE s.tenant_id = tq.tenant_id
)
WHERE EXISTS (
    SELECT 1 FROM shared.secrets s WHERE s.tenant_id = tq.tenant_id
);
