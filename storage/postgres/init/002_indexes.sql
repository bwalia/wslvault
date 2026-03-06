-- WSLVault Hot-Path Indexes
-- Designed for the primary read/write/expiration patterns.

-- =============================================================================
-- System schema indexes
-- =============================================================================

-- Tenant lookup by slug (login/routing)
CREATE INDEX idx_tenants_slug ON system.tenants(slug) WHERE deleted_at IS NULL;

-- Key lookup: active keys for a tenant
CREATE INDEX idx_key_descriptors_tenant_active
    ON system.key_descriptors(tenant_id, purpose)
    WHERE state = 'active';

-- =============================================================================
-- Shared schema indexes
-- =============================================================================

-- Primary secret lookup: tenant + path (the hot path for every read)
CREATE INDEX idx_secrets_tenant_path
    ON shared.secrets(tenant_id, path);

-- Secret version fetch: latest version for a secret
CREATE INDEX idx_secret_versions_secret_version
    ON shared.secret_versions(secret_id, version DESC);

-- Lease expiration sweep: find expired active leases
CREATE INDEX idx_leases_expiration
    ON shared.leases(expires_at)
    WHERE state = 'active';

-- Lease lookup by tenant
CREATE INDEX idx_leases_tenant_state
    ON shared.leases(tenant_id, state);

-- Principal lookup by tenant
CREATE INDEX idx_principals_tenant
    ON shared.principals(tenant_id)
    WHERE deleted_at IS NULL;

-- Policy lookup by tenant
CREATE INDEX idx_policies_tenant
    ON shared.policies(tenant_id);

-- Audit log: tenant + time range queries
CREATE INDEX idx_audit_events_tenant_time
    ON shared.audit_events(tenant_id, timestamp DESC);

-- Audit log: action type queries
CREATE INDEX idx_audit_events_action
    ON shared.audit_events(action, timestamp DESC);
