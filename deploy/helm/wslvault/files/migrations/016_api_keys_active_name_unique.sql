-- Scope API key name uniqueness to ACTIVE keys.
-- Migration: 016_api_keys_active_name_unique.sql
--
-- 005 created `api_keys_tenant_name_unique UNIQUE (tenant_id, name)` across
-- every row regardless of revocation. Rotation — revoke the old key, mint a
-- replacement carrying the same name — therefore cannot be persisted: the
-- revoked row still occupies the (tenant_id, name) slot and the insert fails.
--
-- The manager has always scoped its duplicate-name check to non-revoked keys,
-- so this brings the schema in line with the behaviour the service implements
-- and with the audit trail we want: revoked keys stay in the table forever.

ALTER TABLE shared.api_keys
    DROP CONSTRAINT IF EXISTS api_keys_tenant_name_unique;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_tenant_name_active
    ON shared.api_keys (tenant_id, name)
    WHERE revoked_at IS NULL;
