-- WSLVault Dedicated / Sovereign Tenant Schema Provisioning
--
-- Tenants on the "dedicated" or "sovereign" tier receive their own isolated
-- PostgreSQL schema instead of sharing `shared.*` tables with other tenants.
--
-- This migration creates:
-- 1. A stored function to provision a new per-tenant schema.
-- 2. A stored function to drop a per-tenant schema (on tenant deletion).
-- 3. A system table to track provisioned schemas.
--
-- Apply after 012_tenant_quotas.sql.

-- =============================================================================
-- 1. Schema registry — tracks which tenants have dedicated schemas
-- =============================================================================

CREATE TABLE IF NOT EXISTS system.tenant_schemas (
    tenant_id        UUID PRIMARY KEY REFERENCES system.tenants(id) ON DELETE CASCADE,
    schema_name      TEXT NOT NULL UNIQUE,
    tier             TEXT NOT NULL CHECK (tier IN ('dedicated', 'sovereign')),
    provisioned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL when active; set when the schema is scheduled for cleanup.
    deprovisioned_at TIMESTAMPTZ
);

COMMENT ON TABLE system.tenant_schemas IS
    'Registry of per-tenant PostgreSQL schemas for dedicated/sovereign tenants.';

-- =============================================================================
-- 2. provision_tenant_schema(tenant_uuid, tier_text)
--
-- Creates a schema named "tenant_<uuid_hex>" (hyphens stripped for
-- compatibility with SQL identifiers) and populates it with the same table
-- structure as the shared schema.  Also creates RLS policies scoped to the
-- single tenant, indexes, and updated_at triggers.
--
-- Returns the schema name on success.
-- =============================================================================

CREATE OR REPLACE FUNCTION system.provision_tenant_schema(
    p_tenant_id UUID,
    p_tier      TEXT DEFAULT 'dedicated'
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $fn$
DECLARE
    v_schema TEXT;
BEGIN
    -- Derive schema name: "tenant_<hex>" (no hyphens).
    v_schema := 'tenant_' || replace(p_tenant_id::text, '-', '');

    -- Guard against double-provisioning.
    IF EXISTS (
        SELECT 1 FROM system.tenant_schemas
        WHERE tenant_id = p_tenant_id AND deprovisioned_at IS NULL
    ) THEN
        RAISE NOTICE 'schema already provisioned for tenant %', p_tenant_id;
        RETURN v_schema;
    END IF;

    -- Create the isolated schema.
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', v_schema);

    -- -----------------------------------------------------------------------
    -- Secrets
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.secrets (
            id              UUID PRIMARY KEY,
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            path            TEXT NOT NULL,
            engine          TEXT NOT NULL
                            CHECK (engine IN ('kv_v2','transit','dynamic_database','ssh','pki','cloud_aws','cloud_gcp','cloud_azure')),
            current_version INTEGER NOT NULL DEFAULT 0,
            max_versions    INTEGER NOT NULL DEFAULT 10,
            cas_required    BOOLEAN NOT NULL DEFAULT false,
            custom_metadata JSONB NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, path)
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    -- -----------------------------------------------------------------------
    -- Secret versions
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.secret_versions (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            secret_id       UUID NOT NULL REFERENCES %I.secrets(id) ON DELETE CASCADE,
            version         INTEGER NOT NULL,
            ciphertext      TEXT NOT NULL,
            dek_id          TEXT NOT NULL,
            custom_metadata JSONB NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at      TIMESTAMPTZ,
            destroyed       BOOLEAN NOT NULL DEFAULT false,
            UNIQUE (secret_id, version)
        )
    $t$, v_schema, v_schema);

    -- -----------------------------------------------------------------------
    -- Leases
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.leases (
            id              UUID PRIMARY KEY,
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            target_type     TEXT NOT NULL
                            CHECK (target_type IN ('token','dynamic_secret','service_credential')),
            target_data     JSONB NOT NULL,
            state           TEXT NOT NULL
                            CHECK (state IN ('active','renewing','expired','revoked')) DEFAULT 'active',
            ttl_seconds     BIGINT NOT NULL,
            max_ttl_seconds BIGINT NOT NULL,
            renewable       BOOLEAN NOT NULL DEFAULT true,
            issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at      TIMESTAMPTZ NOT NULL,
            revoked_at      TIMESTAMPTZ
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    -- -----------------------------------------------------------------------
    -- Principals
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.principals (
            id              UUID PRIMARY KEY,
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            display_name    TEXT NOT NULL,
            auth_method     TEXT NOT NULL,
            auth_data       JSONB NOT NULL DEFAULT '{}',
            policies        TEXT[] NOT NULL DEFAULT '{}',
            metadata        JSONB NOT NULL DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at      TIMESTAMPTZ
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    -- -----------------------------------------------------------------------
    -- Policies
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.policies (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID NOT NULL DEFAULT %L::uuid
                            CHECK (tenant_id = %L::uuid),
            name            TEXT NOT NULL,
            document        JSONB NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, name)
        )
    $t$, v_schema, p_tenant_id, p_tenant_id);

    -- -----------------------------------------------------------------------
    -- Audit events (non-partitioned in dedicated schemas; volume is bounded)
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TABLE %I.audit_events (
            id              UUID NOT NULL DEFAULT gen_random_uuid(),
            tenant_id       UUID NOT NULL DEFAULT %L::uuid,
            principal_id    TEXT NOT NULL,
            action          TEXT NOT NULL,
            resource        TEXT NOT NULL,
            outcome         TEXT NOT NULL,
            outcome_detail  TEXT,
            details         JSONB NOT NULL DEFAULT '{}',
            client_ip       INET,
            signature       TEXT,
            timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    $t$, v_schema, p_tenant_id);

    -- -----------------------------------------------------------------------
    -- Indexes (mirror shared schema indexes from 002_indexes.sql)
    -- -----------------------------------------------------------------------
    EXECUTE format('CREATE INDEX ON %I.secrets (tenant_id)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.secrets (path)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.secret_versions (secret_id, version)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.leases (tenant_id, state)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.leases (expires_at) WHERE state = ''active''', v_schema);
    EXECUTE format('CREATE INDEX ON %I.principals (tenant_id)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.policies (tenant_id)', v_schema);
    EXECUTE format('CREATE INDEX ON %I.audit_events (tenant_id, timestamp DESC)', v_schema);

    -- -----------------------------------------------------------------------
    -- updated_at triggers
    -- -----------------------------------------------------------------------
    EXECUTE format($t$
        CREATE TRIGGER trg_secrets_updated_at
            BEFORE UPDATE ON %I.secrets
            FOR EACH ROW EXECUTE FUNCTION system.update_updated_at()
    $t$, v_schema);

    EXECUTE format($t$
        CREATE TRIGGER trg_principals_updated_at
            BEFORE UPDATE ON %I.principals
            FOR EACH ROW EXECUTE FUNCTION system.update_updated_at()
    $t$, v_schema);

    EXECUTE format($t$
        CREATE TRIGGER trg_policies_updated_at
            BEFORE UPDATE ON %I.policies
            FOR EACH ROW EXECUTE FUNCTION system.update_updated_at()
    $t$, v_schema);

    -- -----------------------------------------------------------------------
    -- Register in the schema registry
    -- -----------------------------------------------------------------------
    INSERT INTO system.tenant_schemas (tenant_id, schema_name, tier)
    VALUES (p_tenant_id, v_schema, p_tier)
    ON CONFLICT (tenant_id) DO UPDATE
        SET deprovisioned_at = NULL,
            tier             = p_tier;

    RAISE NOTICE 'provisioned schema % for tenant % (tier: %)', v_schema, p_tenant_id, p_tier;
    RETURN v_schema;
END;
$fn$;

COMMENT ON FUNCTION system.provision_tenant_schema(UUID, TEXT) IS
    'Creates an isolated PostgreSQL schema for a dedicated or sovereign tenant. '
    'Tables mirror the shared schema structure with a CHECK constraint pinning '
    'tenant_id to the owning tenant UUID.';

-- =============================================================================
-- 3. deprovision_tenant_schema(tenant_uuid)
--
-- Marks the schema as deprovisioned and drops it.  The registry row is kept
-- for audit purposes (deprovisioned_at is set instead of deleting the row).
-- =============================================================================

CREATE OR REPLACE FUNCTION system.deprovision_tenant_schema(p_tenant_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $fn$
DECLARE
    v_schema TEXT;
BEGIN
    SELECT schema_name INTO v_schema
    FROM system.tenant_schemas
    WHERE tenant_id = p_tenant_id AND deprovisioned_at IS NULL;

    IF v_schema IS NULL THEN
        RAISE NOTICE 'no active schema for tenant %', p_tenant_id;
        RETURN;
    END IF;

    -- Drop the entire schema and all objects within it.
    EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', v_schema);

    UPDATE system.tenant_schemas
    SET deprovisioned_at = now()
    WHERE tenant_id = p_tenant_id;

    RAISE NOTICE 'deprovisioned schema % for tenant %', v_schema, p_tenant_id;
END;
$fn$;

COMMENT ON FUNCTION system.deprovision_tenant_schema(UUID) IS
    'Drops the dedicated schema for a tenant and marks it as deprovisioned.';

-- =============================================================================
-- 4. Helper: resolve the schema name for a tenant
--
-- Returns 'shared' for shared-tier tenants and the per-tenant schema name
-- for dedicated/sovereign tenants.  Used by the application layer to route
-- queries to the correct schema.
-- =============================================================================

CREATE OR REPLACE FUNCTION system.resolve_tenant_schema(p_tenant_id UUID)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        (SELECT schema_name FROM system.tenant_schemas
         WHERE tenant_id = p_tenant_id AND deprovisioned_at IS NULL),
        'shared'
    );
$$;

COMMENT ON FUNCTION system.resolve_tenant_schema(UUID) IS
    'Returns the PostgreSQL schema name for a tenant — either a per-tenant '
    'schema or "shared" for shared-tier tenants.';
