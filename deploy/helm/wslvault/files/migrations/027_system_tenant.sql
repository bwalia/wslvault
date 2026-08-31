-- WSLVault: the reserved tenant that owns system-scope key material.
-- Migration: 027_system_tenant.sql
--
-- ## Why this row has to exist
--
-- Superuser tokens authorise across every tenant, so they are signed by a
-- tenant-less *system* key rather than by any one tenant's — otherwise a single
-- tenant's signing key could mint authority over all the others.
--
-- That key still has to be wrapped, and the crypto-service's envelope API is
-- tenant-scoped by design: tenant scoping is exactly what stops one tenant
-- reading another's key material. Rather than carve an exception through it,
-- the system key is wrapped under a reserved, well-known tenant id.
--
-- Without this row, `system.key_descriptors.tenant_id` has nothing to reference
-- and wrapping fails:
--
--     insert or update on table "key_descriptors" violates foreign key
--     constraint "key_descriptors_tenant_id_fkey"
--
-- which meant superuser tokens could never be issued at all. Found by running
-- the flow against a real database; no unit test would have caught it, because
-- none of them have a foreign key.
--
-- The all-zeros UUID is chosen because it is unmistakably reserved: nothing
-- generates it by accident.

INSERT INTO system.tenants (id, slug, display_name, tier, root_key_id)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system',
    'WSLVault System',
    'shared',
    'system-root'
)
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE system.tenants IS
    'Tenant registry. The all-zeros id is reserved for system-scope key material (see 027) and owns no secrets.';
