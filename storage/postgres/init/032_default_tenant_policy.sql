-- WSLVault: give every tenant a baseline policy.
-- Migration: 032_default_tenant_policy.sql
--
-- ## Why
--
-- Keys issued by invitation carry `["default"]`, but nothing ever created a
-- policy by that name. A policy name that resolves to nothing grants nothing,
-- so an invited member signed in successfully and was then refused on every
-- request — including listing their own tenant's secrets. The failure surfaced
-- as "no policy grants 'list' on resource 'secret/list'".
--
-- `tenant_handlers::seed_default_policy` now writes this at tenant creation.
-- This backfills the tenants that already exist, which otherwise stay unusable
-- for their own members forever.
--
-- Scoped to that tenant's own secrets. It grants no policy management, no key
-- management and nothing cross-tenant: those are deliberate grants, not
-- defaults inherited by existing.

INSERT INTO shared.policies (tenant_id, name, document)
SELECT t.id,
       'default',
       jsonb_build_object(
           'name', 'default',
           'rules', jsonb_build_array(
               jsonb_build_object(
                   -- Covers both resource shapes the engine checks:
                   -- `secret/list` and `secret/data/<path>`.
                   'paths', jsonb_build_array('secret/**'),
                   'capabilities', jsonb_build_array('read', 'write', 'list', 'delete')
               )
           )
       )
FROM system.tenants t
WHERE t.deleted_at IS NULL
ON CONFLICT (tenant_id, name) DO NOTHING;
