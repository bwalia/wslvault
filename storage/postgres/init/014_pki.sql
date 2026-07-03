-- WSLVault PKI Engine Schema
--
-- Creates the `pki` schema and its three tables:
--
--   pki.pki_ca    — one CA record per tenant (cert PEM + AES-256-GCM wrapped key)
--   pki.pki_roles — role definitions controlling what certs may be issued
--   pki.pki_certs — issued certificate metadata, including revocation state
--
-- CA private keys are stored in `encrypted_key_b64` as an AES-256-GCM
-- envelope (base64-encoded nonce‖ciphertext‖tag) produced by the pki-engine
-- using the service-level root KEK from `PKI_ROOT_KEY`.  Raw key material is
-- never written in plaintext to this table.
--
-- Apply after 013_dedicated_tenant_schemas.sql.

-- =============================================================================
-- 0. Schema
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS pki;

COMMENT ON SCHEMA pki IS
    'Internal PKI engine tables: CA records, roles, and issued certificate metadata.';

-- =============================================================================
-- 1. pki_ca — one row per tenant, holding the CA certificate and encrypted key
-- =============================================================================

CREATE TABLE IF NOT EXISTS pki.pki_ca (
    -- Primary key: one CA per tenant.
    tenant_id           UUID        NOT NULL PRIMARY KEY
                                    REFERENCES system.tenants(id) ON DELETE CASCADE,

    -- PEM-encoded self-signed CA certificate (or imported CA cert).
    cert_pem            TEXT        NOT NULL,

    -- AES-256-GCM envelope of the CA private key, base64-encoded.
    -- Format: base64(12-byte nonce ‖ ciphertext ‖ 16-byte GCM tag).
    -- AAD used during encryption: "pki-ca-key:<tenant_id>".
    encrypted_key_b64   TEXT        NOT NULL,

    -- Version of the service-level root KEK used to wrap this key.
    -- Enables future rotation sweeps that re-wrap affected rows.
    key_version         INTEGER     NOT NULL DEFAULT 1,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE pki.pki_ca IS
    'One CA record per tenant.  CA private keys are stored encrypted at rest '
    'using AES-256-GCM with the pki-engine root KEK.';

COMMENT ON COLUMN pki.pki_ca.encrypted_key_b64 IS
    'AES-256-GCM ciphertext envelope (nonce‖ct‖tag) of the CA private key PEM, '
    'base64-encoded.  Never contains plaintext key material.';

COMMENT ON COLUMN pki.pki_ca.key_version IS
    'Root KEK version used to wrap this key.  Allows targeted re-wrapping '
    'during PKI_ROOT_KEY rotation without CA re-issuance.';

-- =============================================================================
-- 2. pki_roles — role definitions per tenant
-- =============================================================================

CREATE TABLE IF NOT EXISTS pki.pki_roles (
    -- Composite primary key: role names are unique per tenant.
    tenant_id           UUID        NOT NULL REFERENCES system.tenants(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,

    -- Domain policy arrays.
    allowed_domains     TEXT[]      NOT NULL DEFAULT '{}',
    allow_subdomains    BOOLEAN     NOT NULL DEFAULT false,
    allow_bare_domains  BOOLEAN     NOT NULL DEFAULT false,

    -- Leaf certificate constraints.
    max_ttl_seconds     BIGINT      NOT NULL DEFAULT 86400,
    key_type            TEXT        NOT NULL DEFAULT 'ecdsa-p256'
                                    CHECK (key_type IN ('ecdsa-p256', 'rsa-2048', 'rsa-4096')),

    -- Extended key usages stored as a JSONB array of string enum values
    -- (e.g. ["server_auth", "client_auth"]).
    key_usages          JSONB       NOT NULL DEFAULT '[]',

    allow_ip_sans       BOOLEAN     NOT NULL DEFAULT false,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, name)
);

COMMENT ON TABLE pki.pki_roles IS
    'PKI role definitions.  Roles constrain what common names, SANs, key types, '
    'and TTLs may appear in certificates issued under that role.';

-- Index for fast role look-ups by tenant.
CREATE INDEX IF NOT EXISTS idx_pki_roles_tenant_id ON pki.pki_roles (tenant_id);

-- updated_at trigger (same pattern used throughout the shared schema).
CREATE OR REPLACE FUNCTION pki.pki_roles_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_pki_roles_updated_at ON pki.pki_roles;
CREATE TRIGGER trg_pki_roles_updated_at
    BEFORE UPDATE ON pki.pki_roles
    FOR EACH ROW EXECUTE FUNCTION pki.pki_roles_set_updated_at();

-- =============================================================================
-- 3. pki_certs — issued certificate metadata and revocation state
-- =============================================================================

CREATE TABLE IF NOT EXISTS pki.pki_certs (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id           UUID        NOT NULL REFERENCES system.tenants(id) ON DELETE CASCADE,

    -- The role used to issue this certificate.
    role_name           TEXT        NOT NULL,

    -- X.509 serial number (lowercase hex, e.g. "0a1b2c3d4e5f6a7b").
    serial              TEXT        NOT NULL,

    -- Subject Common Name of the issued certificate.
    common_name         TEXT        NOT NULL DEFAULT '',

    -- Certificate validity window.
    not_after           TIMESTAMPTZ NOT NULL,

    -- NULL when not revoked; set to the revocation timestamp on POST /revoke.
    revoked_at          TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Enforce serial uniqueness per tenant (serials are random 8-byte hex
    -- strings so collision probability is negligible, but duplicates would
    -- break CRL semantics).
    UNIQUE (tenant_id, serial)
);

COMMENT ON TABLE pki.pki_certs IS
    'Metadata for every certificate issued by the PKI engine.  Includes '
    'revocation state used to build on-demand CRLs.';

COMMENT ON COLUMN pki.pki_certs.serial IS
    'X.509 serial number stored as lowercase hex.  Unique per tenant.';

COMMENT ON COLUMN pki.pki_certs.revoked_at IS
    'NULL = certificate is valid.  Non-NULL = certificate has been revoked; '
    'value is the UTC timestamp of the POST /v1/pki/revoke call.';

-- Index for CRL generation (fetch all revoked certs for a tenant efficiently).
CREATE INDEX IF NOT EXISTS idx_pki_certs_tenant_revoked
    ON pki.pki_certs (tenant_id, revoked_at)
    WHERE revoked_at IS NOT NULL;

-- Index for active-cert listing (e.g. quota enforcement, auditing).
CREATE INDEX IF NOT EXISTS idx_pki_certs_tenant_active
    ON pki.pki_certs (tenant_id, not_after)
    WHERE revoked_at IS NULL;
