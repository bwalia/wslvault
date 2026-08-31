-- WSLVault: give key descriptors a name, so transit keys can be persisted.
-- Migration: 021_transit_key_names.sql
--
-- ## Why
--
-- `system.key_descriptors` had no name column. Transit keys are addressed by
-- name (`/v1/transit/keys/:name`), so there was no way to write one down —
-- which is a large part of why transit key material was never persisted at
-- all and `wrapped_key` held the literal string "TODO:wrap_key_material".
--
-- It also made rotation wrong in a way that only shows up with more than one
-- key: `rotate_key` located the row to retire with
-- `get_active_key(pool, tenant, Transit)`, which returns *the* active transit
-- descriptor for the tenant. With two transit keys, rotating key B transitioned
-- key A's descriptor to `rotating_out`.
--
-- DEKs and KEKs are addressed by id and leave this NULL.

ALTER TABLE system.key_descriptors
    ADD COLUMN IF NOT EXISTS key_name TEXT;

COMMENT ON COLUMN system.key_descriptors.key_name IS
    'Caller-facing name for keys addressed by name (transit). NULL for DEKs and KEKs, which are addressed by id.';

-- Rotation and warm-load both look up "this tenant's key called N".
CREATE INDEX IF NOT EXISTS idx_key_descriptors_tenant_name
    ON system.key_descriptors (tenant_id, key_name, version)
    WHERE key_name IS NOT NULL;

-- One active descriptor per (tenant, name, version). Without this a retried
-- rotation could insert a duplicate version and warm-load would pick between
-- them arbitrarily.
CREATE UNIQUE INDEX IF NOT EXISTS uq_key_descriptors_tenant_name_version
    ON system.key_descriptors (tenant_id, key_name, version)
    WHERE key_name IS NOT NULL AND state <> 'destroyed';
