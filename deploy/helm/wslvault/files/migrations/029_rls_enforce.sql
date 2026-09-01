-- WSLVault: close the RLS coverage gaps and prepare enforcement.
-- Migration: 029_rls_enforce.sql
--
-- ## Why this is 029 and not 019
--
-- 018_rls_correctness.sql ends by saying the enforcement work "lives in
-- 019_rls_enforce.sql". That file was never written, and it can no longer be
-- called 019: migrate.sh applies files once, in name order, tracked by
-- checksum in system.schema_migrations. A new 019 would run BEFORE 020-028 on
-- a fresh database and AFTER them on the live ones, so the two would diverge
-- on exactly the tables this migration has to touch. 029 runs last in both.
--
-- 018 also cannot be edited to correct the pointer: migrate.sh compares the
-- recorded checksum and aborts with "an applied migration was edited in
-- place" if it changes. The pointer stays wrong; this header is the fix.
--
-- ## Correcting the record: FORCE is not a no-op here
--
-- 018 gives three reasons RLS was inert, and the second one is wrong for this
-- deployment. It says the app role "is a superuser with rolbypassrls", which
-- would make FORCE ROW LEVEL SECURITY harmless. Checked against the live
-- region-A database:
--
--   SELECT rolname, rolsuper, rolbypassrls FROM pg_roles;
--    postgres  | t | t
--    wslvault  | f | f      <-- not a superuser, does not bypass RLS
--
-- `wslvault` is exempt for ONE reason only: it owns the tables, and owners are
-- exempt until FORCE ROW LEVEL SECURITY is set. That makes FORCE the live
-- switch, not a formality. Setting it today — while no code executes
-- `SET app.current_tenant_id` — makes every fail-closed policy match zero rows
-- and takes both regions down.
--
-- So this migration deliberately does NOT force. It does the half that is safe
-- to apply ahead of the application change:
--
--   1. Extends RLS to the seven tenant-scoped tables that have none.
--   2. Makes the write-side check explicit on every policy.
--   3. Adds shared.rls_status(), so "is isolation actually enforced?" is one
--      query rather than an argument.
--   4. Grants the least-privilege role its object permissions, if it exists.
--
-- Enabling RLS without forcing it changes nothing for the owner — which is
-- what every service still connects as — so this is safe to apply to a live
-- region. 030_rls_force_secrets.sql holds the switch, and must not be applied
-- until the services set the session variable.

-- =============================================================================
-- 1. Coverage: the tenant-scoped tables 004 and 011 never enabled RLS on
-- =============================================================================
-- Every table below carries a tenant_id and had no row-level security at all,
-- so a session that reached the database saw all tenants' rows. They were
-- protected only by the application's own WHERE clauses.

-- Rotation records. This one is not theoretical: shared.vault_confirm_rotation
-- resolves a rotation by id with no tenant predicate (010_secret_lifecycle.sql),
-- and secret-engine's handler authorises against the caller's tenant but then
-- passes the bare rotation_id through. A tenant holding a rotation UUID can
-- confirm another tenant's rotation today.
ALTER TABLE shared.secret_rotations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_secret_rotations ON shared.secret_rotations;
CREATE POLICY tenant_isolation_secret_rotations ON shared.secret_rotations
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- Per-tenant quota counters.
ALTER TABLE shared.tenant_quotas ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_tenant_quotas ON shared.tenant_quotas;
CREATE POLICY tenant_isolation_tenant_quotas ON shared.tenant_quotas
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- SCIM group membership carries no tenant_id of its own; it inherits the
-- tenant of the group it points at, the same way secret_versions inherits
-- from secrets.
ALTER TABLE shared.scim_group_members ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_scim_group_members ON shared.scim_group_members;
CREATE POLICY tenant_isolation_scim_group_members ON shared.scim_group_members
    USING (EXISTS (
        SELECT 1 FROM shared.scim_groups g
        WHERE g.id = shared.scim_group_members.group_id
          AND shared.rls_tenant_visible_text(g.tenant_id)
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM shared.scim_groups g
        WHERE g.id = shared.scim_group_members.group_id
          AND shared.rls_tenant_visible_text(g.tenant_id)
    ));

-- Wrapped key material. 004 excluded system.* wholesale on the grounds that
-- cross-tenant jobs use it — but key_descriptors is where each tenant's KEK
-- and every per-encrypt DEK lives, and it has carried a tenant_id since 001.
--
-- tenant_id is NULL for the root KEK, which belongs to no tenant. A NULL makes
-- the predicate NULL, so root-KEK rows are invisible to every tenant session
-- and visible only under app.bypass_rls. That is the intended reading:
-- crypto-service's root-key work is a cross-tenant job and must say so.
ALTER TABLE system.key_descriptors ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_key_descriptors ON system.key_descriptors;
CREATE POLICY tenant_isolation_key_descriptors ON system.key_descriptors
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- Per-tenant Ed25519 signing keys — the private half of the JWKS that gives
-- each tenant its own token-signing boundary.
ALTER TABLE system.tenant_signing_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_signing_keys ON system.tenant_signing_keys;
CREATE POLICY tenant_isolation_signing_keys ON system.tenant_signing_keys
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- Revoked token hashes. tenant_id is TEXT here.
ALTER TABLE system.revoked_tokens ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_revoked_tokens ON system.revoked_tokens;
CREATE POLICY tenant_isolation_revoked_tokens ON system.revoked_tokens
    USING (shared.rls_tenant_visible_text(tenant_id))
    WITH CHECK (shared.rls_tenant_visible_text(tenant_id));

-- Connector sync jobs.
ALTER TABLE system.sync_jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_sync_jobs ON system.sync_jobs;
CREATE POLICY tenant_isolation_sync_jobs ON system.sync_jobs
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- Dedicated/sovereign tenant schema registry.
ALTER TABLE system.tenant_schemas ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_tenant_schemas ON system.tenant_schemas;
CREATE POLICY tenant_isolation_tenant_schemas ON system.tenant_schemas
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

-- =============================================================================
-- 2. Make the write-side check explicit on the policies 004/011/018 created
-- =============================================================================
-- A `FOR ALL ... USING (x)` policy with no WITH CHECK reuses the USING
-- expression for INSERT and UPDATE, so writes were already constrained. Making
-- it explicit costs nothing and removes the need to know that rule to read the
-- policy — the difference between "writes happen to be covered" and "writes are
-- stated to be covered" matters on a table holding other tenants' secrets.

DROP POLICY IF EXISTS tenant_isolation_secrets ON shared.secrets;
CREATE POLICY tenant_isolation_secrets ON shared.secrets
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_secret_versions ON shared.secret_versions;
CREATE POLICY tenant_isolation_secret_versions ON shared.secret_versions
    USING (EXISTS (
        SELECT 1 FROM shared.secrets s
        WHERE s.id = shared.secret_versions.secret_id
          AND shared.rls_tenant_visible(s.tenant_id)
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM shared.secrets s
        WHERE s.id = shared.secret_versions.secret_id
          AND shared.rls_tenant_visible(s.tenant_id)
    ));

DROP POLICY IF EXISTS tenant_isolation_leases ON shared.leases;
CREATE POLICY tenant_isolation_leases ON shared.leases
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_policies ON shared.policies;
CREATE POLICY tenant_isolation_policies ON shared.policies
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_principals ON shared.principals;
CREATE POLICY tenant_isolation_principals ON shared.principals
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_api_keys ON shared.api_keys;
CREATE POLICY tenant_isolation_api_keys ON shared.api_keys
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_mfa_totp ON shared.mfa_totp;
CREATE POLICY tenant_isolation_mfa_totp ON shared.mfa_totp
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_mfa_recovery ON shared.mfa_recovery_codes;
CREATE POLICY tenant_isolation_mfa_recovery ON shared.mfa_recovery_codes
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS scim_users_tenant_isolation ON shared.scim_users;
CREATE POLICY scim_users_tenant_isolation ON shared.scim_users
    USING (shared.rls_tenant_visible_text(tenant_id))
    WITH CHECK (shared.rls_tenant_visible_text(tenant_id));

DROP POLICY IF EXISTS scim_groups_tenant_isolation ON shared.scim_groups;
CREATE POLICY scim_groups_tenant_isolation ON shared.scim_groups
    USING (shared.rls_tenant_visible_text(tenant_id))
    WITH CHECK (shared.rls_tenant_visible_text(tenant_id));

-- audit_events is partitioned. Policies on the parent cover reads and writes
-- that go THROUGH the parent, which is how the application accesses it, but a
-- query naming a partition directly is checked against that partition's own
-- RLS — which is off. Cover the existing partitions too, and note the standing
-- requirement for any partition added later.
DROP POLICY IF EXISTS tenant_isolation_audit ON shared.audit_events;
CREATE POLICY tenant_isolation_audit ON shared.audit_events
    USING (shared.rls_tenant_visible(tenant_id))
    WITH CHECK (shared.rls_tenant_visible(tenant_id));

DO $$
DECLARE part regclass;
BEGIN
    FOR part IN
        SELECT inhrelid::regclass
        FROM pg_inherits
        WHERE inhparent = 'shared.audit_events'::regclass
    LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', part);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_audit_part ON %s', part);
        EXECUTE format(
            'CREATE POLICY tenant_isolation_audit_part ON %s '
            'USING (shared.rls_tenant_visible(tenant_id)) '
            'WITH CHECK (shared.rls_tenant_visible(tenant_id))', part);
    END LOOP;
END $$;

COMMENT ON TABLE shared.audit_events IS
    'Partitioned. Any partition added later must repeat the ENABLE ROW LEVEL '
    'SECURITY and tenant_isolation_audit_part policy from 029, or a direct '
    'query on that partition bypasses tenant isolation.';

-- =============================================================================
-- 3. shared.rls_status(): make the state of enforcement answerable
-- =============================================================================
-- The reason RLS could sit inert for this long is that nothing reported on it.
-- "RLS is enabled" was true and meant nothing. This returns the three facts
-- that together decide whether a table is actually protected, so a drift check
-- or a test can assert on them.

CREATE OR REPLACE FUNCTION shared.rls_status()
RETURNS TABLE (
    tbl            text,
    rls_enabled    boolean,
    rls_forced     boolean,
    policy_count   integer,
    owner_exempt   boolean,
    enforced       boolean
)
LANGUAGE sql STABLE
AS $$
    SELECT
        (n.nspname || '.' || c.relname)::text,
        c.relrowsecurity,
        c.relforcerowsecurity,
        (SELECT count(*)::integer FROM pg_policy p WHERE p.polrelid = c.oid),
        -- The owner ignores RLS unless it is FORCEd. Every service connects as
        -- the owner today, so this column is the one that matters.
        NOT c.relforcerowsecurity,
        -- Enforced for the owner only when RLS is on, FORCEd, and a policy exists.
        c.relrowsecurity
            AND c.relforcerowsecurity
            AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ('shared', 'system')
      AND c.relkind IN ('r', 'p')
      AND (
          -- Tenant-scoped by its own column.
          EXISTS (
              SELECT 1 FROM information_schema.columns col
              WHERE col.table_schema = n.nspname
                AND col.table_name = c.relname
                AND col.column_name = 'tenant_id'
          )
          -- Or tenant-scoped through a parent row, which is how
          -- shared.secret_versions and shared.scim_group_members inherit their
          -- tenant. Keying only on the column would have quietly omitted the
          -- table holding the actual ciphertext.
          OR EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
      )
    ORDER BY 1;
$$;

COMMENT ON FUNCTION shared.rls_status() IS
    'Per-table row-level-security state for every tenant-scoped table. '
    '`enforced` is false while services connect as the table owner and FORCE '
    'ROW LEVEL SECURITY is unset — which is the state 029 leaves the system in '
    'deliberately. See 030_rls_force_secrets.sql.';

-- =============================================================================
-- 4. Object grants for the least-privilege role, if it has been created
-- =============================================================================
-- The role itself cannot be created here: the migration Job connects as
-- `wslvault`, which has neither SUPERUSER nor CREATEROLE, so CREATE ROLE fails.
-- An operator creates it once as `postgres` using
-- deploy/helm/wslvault/files/bootstrap/rls_app_role.sql. This block grants the
-- object permissions when the role is present and says so plainly when it is
-- not, rather than failing a migration that is otherwise complete.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wslvault_app') THEN
        RAISE NOTICE
            'role wslvault_app does not exist: skipping grants. Enforcement '
            'stays off until an operator runs bootstrap/rls_app_role.sql as a '
            'superuser and the services are pointed at that role.';
        RETURN;
    END IF;

    EXECUTE 'GRANT USAGE ON SCHEMA shared, system TO wslvault_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shared, system TO wslvault_app';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA shared, system TO wslvault_app';
    EXECUTE 'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA shared, system TO wslvault_app';

    -- Tables created by later migrations must not silently land without grants.
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA shared, system '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO wslvault_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA shared, system '
            'GRANT USAGE, SELECT ON SEQUENCES TO wslvault_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA shared, system '
            'GRANT EXECUTE ON FUNCTIONS TO wslvault_app';

    RAISE NOTICE 'granted object permissions on shared and system to wslvault_app';
END $$;
