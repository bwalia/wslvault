-- WSLVault Secret Lifecycle Extension
-- Adds secret types (EPHEMERAL, STALE_TTL, ROTATION_REQUIRED), rotation
-- coordination, version status tracking, and rollback capability.
--
-- Apply after 009_sync_jobs.sql.

-- =============================================================================
-- 1. Extend shared.secrets with lifecycle columns
-- =============================================================================

ALTER TABLE shared.secrets
    ADD COLUMN IF NOT EXISTS secret_type TEXT NOT NULL DEFAULT 'STALE_TTL'
        CHECK (secret_type IN ('EPHEMERAL', 'STALE_TTL', 'ROTATION_REQUIRED')),
    ADD COLUMN IF NOT EXISTS ttl_seconds INTEGER,              -- EPHEMERAL / STALE_TTL
    ADD COLUMN IF NOT EXISTS soft_warn_seconds INTEGER,        -- STALE_TTL soft-warning threshold
    ADD COLUMN IF NOT EXISTS rotation_interval_seconds INTEGER, -- ROTATION_REQUIRED interval
    ADD COLUMN IF NOT EXISTS grace_period_seconds INTEGER DEFAULT 3600, -- post-rotation revoke grace
    ADD COLUMN IF NOT EXISTS webhook_url TEXT,                 -- rotation notification target
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,           -- computed at write from ttl_seconds
    ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS next_rotation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rotation_status TEXT NOT NULL DEFAULT 'none'
        CHECK (rotation_status IN ('none', 'pending', 'confirmed'));

COMMENT ON COLUMN shared.secrets.secret_type IS
    'EPHEMERAL: short-lived, TTL-enforced; STALE_TTL: has TTL with soft warnings; '
    'ROTATION_REQUIRED: must be rotated periodically with app coordination.';

-- =============================================================================
-- 2. Extend shared.secret_versions with version status
-- =============================================================================

ALTER TABLE shared.secret_versions
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deprecated', 'revoked', 'pending')),
    ADD COLUMN IF NOT EXISTS created_by TEXT,        -- principal ID that wrote this version
    ADD COLUMN IF NOT EXISTS deprecated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

COMMENT ON COLUMN shared.secret_versions.status IS
    'active: current readable version; deprecated: superseded, readable by power_admin only; '
    'revoked: grace period expired, data destroyed; pending: awaiting rotation confirmation.';

-- =============================================================================
-- 3. Rotation tracking table
-- =============================================================================

CREATE TABLE IF NOT EXISTS shared.secret_rotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES shared.secrets(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    path            TEXT NOT NULL,
    old_version     INTEGER NOT NULL,
    new_version     INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending_activation'
        CHECK (status IN ('pending_activation', 'confirmed', 'completed', 'expired', 'failed')),
    initiated_by    TEXT NOT NULL,            -- principal ID
    confirmed_by    TEXT,                     -- principal ID that confirmed
    webhook_url     TEXT,
    webhook_sent_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at    TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    grace_ends_at   TIMESTAMPTZ,              -- when old version gets revoked
    expires_at      TIMESTAMPTZ NOT NULL      -- rotation confirmation timeout
        DEFAULT (now() + INTERVAL '24 hours')
);

CREATE INDEX IF NOT EXISTS idx_secret_rotations_secret_id
    ON shared.secret_rotations(secret_id)
    WHERE status IN ('pending_activation', 'confirmed');

CREATE INDEX IF NOT EXISTS idx_secret_rotations_tenant
    ON shared.secret_rotations(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_rotations_expires
    ON shared.secret_rotations(expires_at)
    WHERE status = 'pending_activation';

-- =============================================================================
-- 4. Indexes for new lifecycle columns
-- =============================================================================

-- Find secrets expiring soon (TTL-based sweep job)
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at
    ON shared.secrets(expires_at)
    WHERE expires_at IS NOT NULL;

-- Find secrets due for rotation
CREATE INDEX IF NOT EXISTS idx_secrets_next_rotation
    ON shared.secrets(next_rotation_at)
    WHERE next_rotation_at IS NOT NULL AND secret_type = 'ROTATION_REQUIRED';

-- Find pending version status transitions
CREATE INDEX IF NOT EXISTS idx_secret_versions_status
    ON shared.secret_versions(secret_id, status)
    WHERE status != 'active';

-- =============================================================================
-- 5. SQL Functions — Rotation Workflow
-- =============================================================================

-- Phase 1: Initiate rotation.
-- Creates a new 'pending' version and a rotation record. Returns the rotation_id
-- and the new version number.
CREATE OR REPLACE FUNCTION shared.vault_initiate_rotation(
    p_tenant_id     UUID,
    p_path          TEXT,
    p_ciphertext    TEXT,
    p_dek_id        TEXT,
    p_initiated_by  TEXT,
    p_webhook_url   TEXT DEFAULT NULL,
    p_timeout_secs  INTEGER DEFAULT 86400   -- 24h default confirmation window
) RETURNS TABLE (
    rotation_id     UUID,
    new_version     INTEGER
) AS $$
DECLARE
    v_secret_id     UUID;
    v_old_version   INTEGER;
    v_new_version   INTEGER;
    v_rotation_id   UUID;
BEGIN
    -- Look up the secret
    SELECT id, current_version
    INTO v_secret_id, v_old_version
    FROM shared.secrets
    WHERE tenant_id = p_tenant_id AND path = p_path
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'secret not found: %', p_path
            USING ERRCODE = 'P0002';
    END IF;

    -- Reject if there is already a pending rotation
    IF EXISTS (
        SELECT 1 FROM shared.secret_rotations
        WHERE secret_id = v_secret_id
          AND status = 'pending_activation'
    ) THEN
        RAISE EXCEPTION 'rotation already pending for secret: %', p_path
            USING ERRCODE = 'P0001';
    END IF;

    -- Insert the new version in 'pending' status (not yet active)
    v_new_version := v_old_version + 1;
    INSERT INTO shared.secret_versions
        (secret_id, version, ciphertext, dek_id, status, created_by)
    VALUES
        (v_secret_id, v_new_version, p_ciphertext, p_dek_id, 'pending', p_initiated_by);

    -- Create the rotation record
    v_rotation_id := gen_random_uuid();
    INSERT INTO shared.secret_rotations
        (id, secret_id, tenant_id, path, old_version, new_version,
         initiated_by, webhook_url, expires_at)
    VALUES
        (v_rotation_id, v_secret_id, p_tenant_id, p_path,
         v_old_version, v_new_version, p_initiated_by, p_webhook_url,
         -- COALESCE: callers may pass an explicit NULL, which would bypass the
         -- parameter default and violate the NOT NULL constraint on expires_at.
         now() + (COALESCE(p_timeout_secs, 86400) * INTERVAL '1 second'));

    -- Update secrets table rotation_status
    UPDATE shared.secrets
    SET rotation_status = 'pending'
    WHERE id = v_secret_id;

    RETURN QUERY SELECT v_rotation_id, v_new_version;
END;
$$ LANGUAGE plpgsql;

-- Phase 2/3: Confirm rotation — activate new version, deprecate old.
CREATE OR REPLACE FUNCTION shared.vault_confirm_rotation(
    p_rotation_id   UUID,
    p_confirmed_by  TEXT
) RETURNS TABLE (
    old_version     INTEGER,
    new_version     INTEGER,
    grace_ends_at   TIMESTAMPTZ
) AS $$
DECLARE
    v_secret_id     UUID;
    v_old_ver       INTEGER;
    v_new_ver       INTEGER;
    v_grace_secs    INTEGER;
    v_grace_end     TIMESTAMPTZ;
BEGIN
    -- Lock and validate the rotation record. Columns are alias-qualified
    -- because the RETURNS TABLE output names old_version/new_version would
    -- otherwise make the references ambiguous.
    SELECT sr.secret_id, sr.old_version, sr.new_version
    INTO v_secret_id, v_old_ver, v_new_ver
    FROM shared.secret_rotations sr
    WHERE sr.id = p_rotation_id
      AND sr.status = 'pending_activation'
      AND sr.expires_at > now()
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'rotation % not found or expired', p_rotation_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Fetch grace period from the secret
    SELECT COALESCE(grace_period_seconds, 3600)
    INTO v_grace_secs
    FROM shared.secrets
    WHERE id = v_secret_id;

    v_grace_end := now() + (v_grace_secs * INTERVAL '1 second');

    -- Activate the new version
    UPDATE shared.secret_versions
    SET status = 'active'
    WHERE secret_id = v_secret_id AND version = v_new_ver;

    -- Deprecate the old version
    UPDATE shared.secret_versions
    SET status = 'deprecated', deprecated_at = now()
    WHERE secret_id = v_secret_id AND version = v_old_ver;

    -- Advance the secret's current_version pointer
    UPDATE shared.secrets
    SET current_version  = v_new_ver,
        rotation_status  = 'confirmed',
        last_rotated_at  = now(),
        next_rotation_at = CASE
            WHEN rotation_interval_seconds IS NOT NULL
            THEN now() + (rotation_interval_seconds * INTERVAL '1 second')
            ELSE NULL
        END
    WHERE id = v_secret_id;

    -- Mark the rotation confirmed
    UPDATE shared.secret_rotations
    SET status        = 'confirmed',
        confirmed_by  = p_confirmed_by,
        confirmed_at  = now(),
        grace_ends_at = v_grace_end
    WHERE id = p_rotation_id;

    RETURN QUERY SELECT v_old_ver, v_new_ver, v_grace_end;
END;
$$ LANGUAGE plpgsql;

-- Phase 4: Revoke old version after grace period expires.
CREATE OR REPLACE FUNCTION shared.vault_revoke_deprecated_versions(
    p_batch_size    INTEGER DEFAULT 100
) RETURNS SETOF UUID AS $$
BEGIN
    RETURN QUERY
    WITH to_revoke AS (
        SELECT r.id AS rotation_id, r.secret_id, r.old_version
        FROM shared.secret_rotations r
        WHERE r.status = 'confirmed'
          AND r.grace_ends_at < now()
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    ),
    updated_versions AS (
        UPDATE shared.secret_versions sv
        SET ciphertext  = '',
            dek_id      = '',
            destroyed   = true,
            deleted_at  = COALESCE(deleted_at, now()),
            status      = 'revoked',
            revoked_at  = now()
        FROM to_revoke tr
        WHERE sv.secret_id = tr.secret_id
          AND sv.version   = tr.old_version
        RETURNING sv.secret_id
    ),
    updated_rotations AS (
        UPDATE shared.secret_rotations r
        SET status       = 'completed',
            completed_at = now()
        FROM to_revoke tr
        WHERE r.id = tr.rotation_id
        RETURNING r.id
    )
    SELECT DISTINCT ur.id FROM updated_rotations ur;
END;
$$ LANGUAGE plpgsql;

-- Rollback: make an older version the current active version.
-- Creates a new version row (audit trail) pointing at the same encrypted data.
CREATE OR REPLACE FUNCTION shared.vault_rollback_secret(
    p_tenant_id     UUID,
    p_path          TEXT,
    p_target_version INTEGER,
    p_rolled_back_by TEXT
) RETURNS TABLE (
    new_version     INTEGER
) AS $$
DECLARE
    v_secret_id     UUID;
    v_current_ver   INTEGER;
    v_new_version   INTEGER;
    v_ciphertext    TEXT;
    v_dek_id        TEXT;
BEGIN
    SELECT id, current_version
    INTO v_secret_id, v_current_ver
    FROM shared.secrets
    WHERE tenant_id = p_tenant_id AND path = p_path
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'secret not found: %', p_path USING ERRCODE = 'P0002';
    END IF;

    -- Fetch the target version's encrypted data
    SELECT ciphertext, dek_id
    INTO v_ciphertext, v_dek_id
    FROM shared.secret_versions
    WHERE secret_id = v_secret_id
      AND version   = p_target_version
      AND destroyed = false;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'version % not found or destroyed for secret %',
            p_target_version, p_path USING ERRCODE = 'P0002';
    END IF;

    v_new_version := v_current_ver + 1;

    -- Copy the target version's ciphertext into a brand-new version row
    INSERT INTO shared.secret_versions
        (secret_id, version, ciphertext, dek_id, status, created_by,
         custom_metadata)
    SELECT
        v_secret_id,
        v_new_version,
        v_ciphertext,
        v_dek_id,
        'active',
        p_rolled_back_by,
        custom_metadata
    FROM shared.secret_versions
    WHERE secret_id = v_secret_id AND version = p_target_version;

    -- Deprecate the previously-active version
    UPDATE shared.secret_versions
    SET status = 'deprecated', deprecated_at = now()
    WHERE secret_id = v_secret_id AND version = v_current_ver AND status = 'active';

    -- Advance current version pointer
    UPDATE shared.secrets
    SET current_version = v_new_version
    WHERE id = v_secret_id;

    RETURN QUERY SELECT v_new_version;
END;
$$ LANGUAGE plpgsql;

-- List all versions with lifecycle metadata (for version history API).
-- Used by the version-history endpoint; does NOT return ciphertext.
CREATE OR REPLACE FUNCTION shared.vault_list_version_history(
    p_tenant_id     UUID,
    p_path          TEXT
) RETURNS TABLE (
    version         INTEGER,
    status          TEXT,
    created_by      TEXT,
    created_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,
    deprecated_at   TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    destroyed       BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        sv.version,
        sv.status,
        sv.created_by,
        sv.created_at,
        sv.deleted_at,
        sv.deprecated_at,
        sv.revoked_at,
        sv.destroyed
    FROM shared.secret_versions sv
    JOIN shared.secrets s ON s.id = sv.secret_id
    WHERE s.tenant_id = p_tenant_id
      AND s.path      = p_path
    ORDER BY sv.version DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 6. Update vault_upsert_secret to populate created_by and set status/expires_at
-- =============================================================================

-- Drop any previous 8/9-param overloads so calling with defaults is unambiguous.
DROP FUNCTION IF EXISTS shared.vault_upsert_secret(uuid, text, text, text, text, integer, integer, boolean);
DROP FUNCTION IF EXISTS shared.vault_upsert_secret(uuid, text, text, text, text, integer, integer, boolean, jsonb);

CREATE OR REPLACE FUNCTION shared.vault_upsert_secret(
    p_tenant_id         UUID,
    p_path              TEXT,
    p_engine            TEXT,
    p_ciphertext        TEXT,
    p_dek_id            TEXT,
    p_cas_version       INTEGER DEFAULT NULL,
    p_max_versions      INTEGER DEFAULT 10,
    p_cas_required      BOOLEAN DEFAULT false,
    p_custom_meta       JSONB DEFAULT '{}',
    p_created_by        TEXT DEFAULT NULL,
    p_secret_type       TEXT DEFAULT 'STALE_TTL',
    p_ttl_seconds       INTEGER DEFAULT NULL,
    p_rotation_interval INTEGER DEFAULT NULL,
    p_grace_secs        INTEGER DEFAULT 3600,
    p_webhook_url       TEXT DEFAULT NULL
) RETURNS TABLE (
    secret_id           UUID,
    new_version         INTEGER
) AS $$
DECLARE
    v_secret_id         UUID;
    v_current_ver       INTEGER;
    v_new_version       INTEGER;
    v_expires_at        TIMESTAMPTZ;
    v_next_rotation_at  TIMESTAMPTZ;
BEGIN
    -- Compute TTL-based expiry
    v_expires_at := CASE
        WHEN p_ttl_seconds IS NOT NULL
        THEN now() + (p_ttl_seconds * INTERVAL '1 second')
        ELSE NULL
    END;

    -- Compute next rotation time
    v_next_rotation_at := CASE
        WHEN p_rotation_interval IS NOT NULL
        THEN now() + (p_rotation_interval * INTERVAL '1 second')
        ELSE NULL
    END;

    -- Upsert the secret metadata
    INSERT INTO shared.secrets (
        id, tenant_id, path, engine, current_version, max_versions, cas_required,
        custom_metadata, secret_type, ttl_seconds, rotation_interval_seconds,
        grace_period_seconds, webhook_url, expires_at, next_rotation_at
    )
    VALUES (
        gen_random_uuid(), p_tenant_id, p_path, p_engine, 0, p_max_versions, p_cas_required,
        p_custom_meta, p_secret_type, p_ttl_seconds, p_rotation_interval,
        p_grace_secs, p_webhook_url, v_expires_at, v_next_rotation_at
    )
    ON CONFLICT (tenant_id, path) DO UPDATE SET
        updated_at = now(),
        -- Update lifecycle fields on each write so they reflect the latest policy
        secret_type = EXCLUDED.secret_type,
        ttl_seconds = COALESCE(EXCLUDED.ttl_seconds, shared.secrets.ttl_seconds),
        rotation_interval_seconds = COALESCE(
            EXCLUDED.rotation_interval_seconds, shared.secrets.rotation_interval_seconds),
        grace_period_seconds = COALESCE(
            EXCLUDED.grace_period_seconds, shared.secrets.grace_period_seconds),
        webhook_url  = COALESCE(EXCLUDED.webhook_url, shared.secrets.webhook_url),
        expires_at   = COALESCE(EXCLUDED.expires_at, shared.secrets.expires_at),
        next_rotation_at = COALESCE(
            EXCLUDED.next_rotation_at, shared.secrets.next_rotation_at)
    RETURNING id, current_version INTO v_secret_id, v_current_ver;

    -- CAS check
    IF p_cas_version IS NOT NULL AND p_cas_version != v_current_ver THEN
        RAISE EXCEPTION 'CAS conflict: expected version %, got %', p_cas_version, v_current_ver
            USING ERRCODE = '40001';
    END IF;

    v_new_version := v_current_ver + 1;

    INSERT INTO shared.secret_versions
        (secret_id, version, ciphertext, dek_id, custom_metadata, status, created_by)
    VALUES
        (v_secret_id, v_new_version, p_ciphertext, p_dek_id, p_custom_meta, 'active', p_created_by);

    UPDATE shared.secrets SET current_version = v_new_version WHERE id = v_secret_id;

    -- Prune old versions beyond max_versions
    DELETE FROM shared.secret_versions sv
    WHERE sv.secret_id = v_secret_id
      AND sv.version   <= (v_new_version - p_max_versions)
      AND sv.destroyed = false;

    RETURN QUERY SELECT v_secret_id, v_new_version;
END;
$$ LANGUAGE plpgsql;
