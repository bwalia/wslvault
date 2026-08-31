-- WSLVault: make Row-Level Security correct, and honest about being inert.
-- Migration: 018_rls_correctness.sql
--
-- ## What was wrong
--
-- RLS was ENABLED on seven tenant tables with correct-looking isolation
-- policies, and enforced on exactly none of them, for three independent
-- reasons:
--
--   1. No application code ever executed `SET app.current_tenant_id`. A grep
--      for it across the whole Rust tree returned zero hits.
--   2. Every service connects as `POSTGRES_USER` (`wslvault`) — which owns
--      these tables AND is a superuser with rolbypassrls. PostgreSQL exempts
--      table owners unless FORCE ROW LEVEL SECURITY is set (it was not), and
--      exempts superusers and BYPASSRLS roles ALWAYS, even with FORCE. So
--      there are two separate reasons this was inert, and fixing only the
--      first would have looked like a fix while changing nothing.
--   3. 011_scim_persistence.sql wrote its policies against a DIFFERENT session
--      variable (`app.tenant_id`) than 004_multitenancy.sql (`app.current_tenant_id`),
--      so the two could never have been satisfied by the same session anyway.
--
-- Tenant isolation therefore rests entirely on the application's own
-- `WHERE tenant_id = $1` clauses. Those are present and correct on the secret
-- paths — but the RLS was documented as a second layer that did not exist.
--
-- ## What this migration does
--
-- It fixes (3) and makes every policy FAIL CLOSED, so that the day the session
-- variable IS wired up, an unset variable shows a session nothing rather than
-- raising an error or — worse — being silently absent.
--
-- `current_setting('app.current_tenant_id', true)` returns NULL when unset
-- (the `true` is missing_ok). `tenant_id = NULL` is NULL, which RLS treats as
-- "row not visible". Unset session ⇒ zero rows. That is the correct default.
--
-- A `app.bypass_rls` escape hatch is provided for the genuinely cross-tenant
-- jobs (crypto-service key rotation, the lease expiry sweep, replication),
-- mirroring the `app.replication_agent` flag 015 already uses.
--
-- ## What this migration deliberately does NOT do
--
-- It does not enable enforcement. That needs a least-privilege role AND the
-- session variable set per transaction; doing either half alone is useless or
-- an outage. 019_rls_enforce.sql holds that work, the verification recipe, and
-- the reason FORCE by itself would have been a false promise.

-- =============================================================================
-- 1. Rewrite the 004 policies to fail closed, with a cross-tenant escape hatch
-- =============================================================================

CREATE OR REPLACE FUNCTION shared.rls_tenant_visible(row_tenant uuid)
    RETURNS boolean
    LANGUAGE sql STABLE
AS $$
    SELECT
        -- Cross-tenant service jobs opt out explicitly and visibly.
        coalesce(current_setting('app.bypass_rls', true) = 'true', false)
        -- Otherwise the row must belong to this session's tenant. An unset or
        -- malformed variable yields NULL, which is not true, so nothing is
        -- visible: fail closed.
        OR row_tenant = nullif(current_setting('app.current_tenant_id', true), '')::uuid;
$$;

COMMENT ON FUNCTION shared.rls_tenant_visible(uuid) IS
    'Row-visibility predicate for tenant RLS. Fails closed when app.current_tenant_id is unset.';

DROP POLICY IF EXISTS tenant_isolation_secrets ON shared.secrets;
CREATE POLICY tenant_isolation_secrets ON shared.secrets
    USING (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_secret_versions ON shared.secret_versions;
CREATE POLICY tenant_isolation_secret_versions ON shared.secret_versions
    USING (
        EXISTS (
            SELECT 1 FROM shared.secrets s
            WHERE s.id = shared.secret_versions.secret_id
              AND shared.rls_tenant_visible(s.tenant_id)
        )
    );

DROP POLICY IF EXISTS tenant_isolation_leases ON shared.leases;
CREATE POLICY tenant_isolation_leases ON shared.leases
    USING (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_policies ON shared.policies;
CREATE POLICY tenant_isolation_policies ON shared.policies
    USING (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_audit ON shared.audit_events;
CREATE POLICY tenant_isolation_audit ON shared.audit_events
    USING (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_principals ON shared.principals;
CREATE POLICY tenant_isolation_principals ON shared.principals
    USING (shared.rls_tenant_visible(tenant_id));

DROP POLICY IF EXISTS tenant_isolation_api_keys ON shared.api_keys;
CREATE POLICY tenant_isolation_api_keys ON shared.api_keys
    USING (shared.rls_tenant_visible(tenant_id));

-- =============================================================================
-- 2. Fix the SCIM policies, which referenced a variable nothing ever sets
-- =============================================================================
-- scim_users.tenant_id / scim_groups.tenant_id are TEXT, not uuid, so they get
-- a text-typed predicate rather than shared.rls_tenant_visible.

CREATE OR REPLACE FUNCTION shared.rls_tenant_visible_text(row_tenant text)
    RETURNS boolean
    LANGUAGE sql STABLE
AS $$
    SELECT
        coalesce(current_setting('app.bypass_rls', true) = 'true', false)
        OR row_tenant = nullif(current_setting('app.current_tenant_id', true), '');
$$;

DROP POLICY IF EXISTS scim_users_tenant_isolation ON shared.scim_users;
CREATE POLICY scim_users_tenant_isolation ON shared.scim_users
    USING (shared.rls_tenant_visible_text(tenant_id));

DROP POLICY IF EXISTS scim_groups_tenant_isolation ON shared.scim_groups;
CREATE POLICY scim_groups_tenant_isolation ON shared.scim_groups
    USING (shared.rls_tenant_visible_text(tenant_id));

-- =============================================================================
-- 3. Make the helper honest
-- =============================================================================
-- shared.current_tenant_id() raised an error when the variable was unset,
-- which is a poor startup check: it cannot distinguish "not configured" from
-- "misconfigured". Return NULL instead so callers can test for it.

CREATE OR REPLACE FUNCTION shared.current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE
AS $$
    SELECT nullif(current_setting('app.current_tenant_id', true), '')::uuid;
$$;

COMMENT ON FUNCTION shared.current_tenant_id() IS
    'The current session tenant, or NULL when app.current_tenant_id is unset.';
