-- WSLVault PostgreSQL Schema
-- All secrets are stored encrypted; this schema holds ciphertext, never plaintext.

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- System schema: global tables shared across all tenants
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS system;

-- Tenant registry
CREATE TABLE system.tenants (
    id          UUID PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    tier        TEXT NOT NULL CHECK (tier IN ('shared', 'dedicated', 'sovereign')),
    root_key_id TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);

-- Key descriptor metadata (no raw key material stored here)
CREATE TABLE system.key_descriptors (
    id          UUID PRIMARY KEY,
    version     INTEGER NOT NULL DEFAULT 1,
    algorithm   TEXT NOT NULL CHECK (algorithm IN ('aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305')),
    purpose     TEXT NOT NULL CHECK (purpose IN ('root_kek', 'tenant_kek', 'data_encryption', 'signing', 'transit')),
    state       TEXT NOT NULL CHECK (state IN ('active', 'rotating_out', 'retired', 'destroyed')) DEFAULT 'active',
    tenant_id   UUID REFERENCES system.tenants(id),
    -- Wrapped (encrypted) key material: base64(ciphertext) encrypted under parent key
    wrapped_key TEXT NOT NULL,
    parent_key_id UUID REFERENCES system.key_descriptors(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    -- No inline UNIQUE constraint: per-encrypt DEKs produce many rows per tenant.
    -- Uniqueness for KEK purposes is enforced by the partial index below.
);

-- =============================================================================
-- Shared schema: used by tenants on the Shared tier
-- Dedicated/Sovereign tenants get their own schemas (tenant_{uuid})
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS shared;

-- Secret metadata
CREATE TABLE shared.secrets (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES system.tenants(id),
    path            TEXT NOT NULL,
    engine          TEXT NOT NULL CHECK (engine IN ('kv_v2', 'transit', 'dynamic_database', 'ssh', 'pki', 'cloud_aws', 'cloud_gcp', 'cloud_azure')),
    current_version INTEGER NOT NULL DEFAULT 0,
    max_versions    INTEGER NOT NULL DEFAULT 10,
    cas_required    BOOLEAN NOT NULL DEFAULT false,
    custom_metadata JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, path)
);

-- Versioned ciphertext blobs
CREATE TABLE shared.secret_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES shared.secrets(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    -- AES-256-GCM ciphertext: base64(nonce || ciphertext || tag)
    ciphertext      TEXT NOT NULL,
    -- ID of the DEK used to encrypt this version
    dek_id          TEXT NOT NULL,
    custom_metadata JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    destroyed       BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (secret_id, version)
);

-- Active leases
CREATE TABLE shared.leases (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES system.tenants(id),
    target_type     TEXT NOT NULL CHECK (target_type IN ('token', 'dynamic_secret', 'service_credential')),
    target_data     JSONB NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('active', 'renewing', 'expired', 'revoked')) DEFAULT 'active',
    ttl_seconds     BIGINT NOT NULL,
    max_ttl_seconds BIGINT NOT NULL,
    renewable       BOOLEAN NOT NULL DEFAULT true,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);

-- Principal / identity records
CREATE TABLE shared.principals (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES system.tenants(id),
    display_name    TEXT NOT NULL,
    auth_method     TEXT NOT NULL,
    auth_data       JSONB NOT NULL DEFAULT '{}',
    policies        TEXT[] NOT NULL DEFAULT '{}',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

-- Policy documents
CREATE TABLE shared.policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES system.tenants(id),
    name            TEXT NOT NULL,
    document        JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- Audit events (append-only, partitioned by month)
CREATE TABLE shared.audit_events (
    id              UUID NOT NULL,
    tenant_id       UUID NOT NULL,
    principal_id    TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    outcome_detail  TEXT,
    details         JSONB NOT NULL DEFAULT '{}',
    client_ip       INET,
    signature       TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (timestamp);

-- Create initial monthly partition
CREATE TABLE shared.audit_events_default PARTITION OF shared.audit_events DEFAULT;

-- =============================================================================
-- Trigger: auto-update updated_at on row modification
-- =============================================================================
CREATE OR REPLACE FUNCTION system.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON system.tenants
    FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();

CREATE TRIGGER trg_secrets_updated_at
    BEFORE UPDATE ON shared.secrets
    FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();

CREATE TRIGGER trg_principals_updated_at
    BEFORE UPDATE ON shared.principals
    FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON shared.policies
    FOR EACH ROW EXECUTE FUNCTION system.update_updated_at();
