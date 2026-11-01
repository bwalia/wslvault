-- WSLVault: let a tenant hold more than one transit key.
-- Migration: 037_transit_multiple_keys_per_tenant.sql
--
-- ## Bug
--
-- 002_indexes.sql made (tenant_id, purpose, version) unique for KEKs, signing
-- keys AND transit keys. That is right for a tenant's single KEK, but transit
-- keys are addressed by name: every transit key starts at version 1, so with
-- the PostgreSQL backend a tenant's second key failed to create with
--
--   duplicate key value violates unique constraint "idx_key_descriptors_kek_unique"
--
-- The in-memory backend (dev and CI) has no such constraint, which is why this
-- went unnoticed. Found while adding Ed25519 keys: an identity provider tenant
-- needs a signing key and an HMAC key side by side.
--
-- ## Fix
--
-- 021_transit_key_names.sql already added the correct constraint for named
-- keys, uq_key_descriptors_tenant_name_version on (tenant_id, key_name,
-- version). Transit only needs to be removed from the old index; the other
-- purposes keep exactly the guarantee they had.

DROP INDEX IF EXISTS system.idx_key_descriptors_kek_unique;

CREATE UNIQUE INDEX IF NOT EXISTS idx_key_descriptors_kek_unique
    ON system.key_descriptors (tenant_id, purpose, version)
    WHERE purpose IN ('tenant_kek', 'root_kek', 'signing');
