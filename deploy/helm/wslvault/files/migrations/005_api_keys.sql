-- API Key Management
-- Migration: 005_api_keys.sql
--
-- API keys provide a simpler alternative to OIDC/JWT for machine-to-machine
-- authentication. Keys are scoped per-tenant and per-path prefix. The raw
-- key is shown once at creation time and never stored; only the SHA-256 hash
-- is persisted.
--
-- Key format: "wslv_" + base64url(32 random bytes)

CREATE TABLE IF NOT EXISTS shared.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES system.tenants(id),
    name VARCHAR(255) NOT NULL,
    -- Store SHA-256 hash of the key, never the raw key
    key_hash BYTEA NOT NULL UNIQUE,
    -- Key prefix for identification (first 8 chars of the key after the "wslv_" prefix)
    key_prefix VARCHAR(12) NOT NULL,
    -- Scoping
    path_prefixes TEXT[] DEFAULT '{}',  -- allowed secret path prefixes (empty = all paths)
    policies TEXT[] DEFAULT '{}',        -- associated policies
    -- Metadata
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,             -- NULL = never expires
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,             -- NULL = active
    -- Rate limiting
    rate_limit_per_minute INT DEFAULT 60,

    CONSTRAINT api_keys_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Fast lookup by hash during authentication (only among active keys).
CREATE INDEX idx_api_keys_key_hash ON shared.api_keys(key_hash) WHERE revoked_at IS NULL;

-- Listing active keys scoped to a tenant.
CREATE INDEX idx_api_keys_tenant ON shared.api_keys(tenant_id) WHERE revoked_at IS NULL;

-- Identification by key prefix (used in UIs and audit logs).
CREATE INDEX idx_api_keys_prefix ON shared.api_keys(key_prefix) WHERE revoked_at IS NULL;

-- Apply the same tenant-isolation RLS policy as the other shared tables so
-- that application sessions scoped to a single tenant cannot read another
-- tenant's key records.
ALTER TABLE shared.api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_api_keys ON shared.api_keys
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
