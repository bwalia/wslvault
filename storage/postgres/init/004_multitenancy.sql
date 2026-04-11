-- WSLVault Multi-Tenancy: Row-Level Security Policies
-- Migration: 004_multitenancy.sql
--
-- Enables row-level security (RLS) on all shared-schema tables that carry
-- tenant_id.  Applications MUST set the session variable before executing
-- any DML on these tables:
--
--   SET app.current_tenant_id = '<uuid>';
--
-- Service accounts that operate cross-tenant (e.g., the crypto-service
-- rotating keys) should connect as a role with BYPASSRLS, or use the
-- system-schema tables (system.tenants, system.key_descriptors) which are
-- intentionally excluded from RLS.
--
-- Note: audit_events is a partitioned table; RLS policies on the parent
-- table are automatically inherited by all existing and future partitions.

-- =============================================================================
-- Secrets
-- =============================================================================
ALTER TABLE shared.secrets ENABLE ROW LEVEL SECURITY;

-- Enforce that each session can only read/write secrets belonging to the
-- tenant identified by the app.current_tenant_id session variable.
CREATE POLICY tenant_isolation_secrets ON shared.secrets
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- =============================================================================
-- Secret versions
-- =============================================================================
ALTER TABLE shared.secret_versions ENABLE ROW LEVEL SECURITY;

-- secret_versions does not carry a direct tenant_id column.  Access is
-- gated by requiring the parent secret to belong to the current tenant.
-- This prevents a caller from reading version blobs by guessing a UUID even
-- if they somehow obtain the secret_id out-of-band.
CREATE POLICY tenant_isolation_secret_versions ON shared.secret_versions
    USING (secret_id IN (
        SELECT id FROM shared.secrets
        WHERE tenant_id = current_setting('app.current_tenant_id')::uuid
    ));

-- =============================================================================
-- Leases
-- =============================================================================
ALTER TABLE shared.leases ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_leases ON shared.leases
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- =============================================================================
-- Policies
-- =============================================================================
ALTER TABLE shared.policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policies ON shared.policies
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- =============================================================================
-- Audit events (partitioned table)
-- =============================================================================
ALTER TABLE shared.audit_events ENABLE ROW LEVEL SECURITY;

-- RLS on audit_events must also cover INSERT so that a misconfigured writer
-- cannot append events attributed to a different tenant.
CREATE POLICY tenant_isolation_audit ON shared.audit_events
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- =============================================================================
-- Principals
-- =============================================================================
ALTER TABLE shared.principals ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_principals ON shared.principals
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- =============================================================================
-- Cross-tenant helper: verify the session variable is properly initialised
-- before any DML reaches the shared tables.
-- =============================================================================
-- This function is called by application startup checks and integration tests
-- to confirm the session variable has been set to a non-empty value.
CREATE OR REPLACE FUNCTION shared.current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE
AS $$
    SELECT current_setting('app.current_tenant_id')::uuid;
$$;

-- =============================================================================
-- NOTE: system.tenants and system.key_descriptors are NOT row-level secured.
-- Those tables are accessed by service accounts that operate cross-tenant
-- (e.g. the crypto-service root KEK rotation job).  Application code that
-- manages tenants should enforce its own authz layer on top.
-- =============================================================================
