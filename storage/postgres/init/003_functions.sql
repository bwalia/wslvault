-- WSLVault PostgreSQL Functions
-- Atomic operations for secret read/write with CAS support.

-- =============================================================================
-- Upsert a secret version with optional check-and-set
-- =============================================================================
CREATE OR REPLACE FUNCTION shared.vault_upsert_secret(
    p_tenant_id     UUID,
    p_path          TEXT,
    p_engine        TEXT,
    p_ciphertext    TEXT,
    p_dek_id        TEXT,
    p_cas_version   INTEGER DEFAULT NULL,
    p_max_versions  INTEGER DEFAULT 10,
    p_cas_required  BOOLEAN DEFAULT false,
    p_custom_meta   JSONB DEFAULT '{}'
) RETURNS TABLE (
    secret_id       UUID,
    new_version     INTEGER
) AS $$
DECLARE
    v_secret_id     UUID;
    v_current_ver   INTEGER;
    v_new_version   INTEGER;
BEGIN
    -- Upsert the secret metadata
    INSERT INTO shared.secrets (id, tenant_id, path, engine, current_version, max_versions, cas_required, custom_metadata)
    VALUES (gen_random_uuid(), p_tenant_id, p_path, p_engine, 0, p_max_versions, p_cas_required, p_custom_meta)
    ON CONFLICT (tenant_id, path) DO UPDATE SET
        updated_at = now()
    RETURNING id, current_version INTO v_secret_id, v_current_ver;

    -- Check-and-set validation
    IF p_cas_version IS NOT NULL AND p_cas_version != v_current_ver THEN
        RAISE EXCEPTION 'CAS conflict: expected version %, got %', p_cas_version, v_current_ver
            USING ERRCODE = '40001'; -- serialization_failure
    END IF;

    -- Increment version
    v_new_version := v_current_ver + 1;

    -- Insert the new version
    INSERT INTO shared.secret_versions (secret_id, version, ciphertext, dek_id, custom_metadata)
    VALUES (v_secret_id, v_new_version, p_ciphertext, p_dek_id, p_custom_meta);

    -- Update current version pointer
    UPDATE shared.secrets SET current_version = v_new_version WHERE id = v_secret_id;

    -- Prune old versions beyond max_versions
    -- Use table alias to avoid ambiguity with the RETURNS TABLE output column 'secret_id'
    DELETE FROM shared.secret_versions sv
    WHERE sv.secret_id = v_secret_id
      AND sv.version <= (v_new_version - p_max_versions)
      AND sv.destroyed = false;

    RETURN QUERY SELECT v_secret_id, v_new_version;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Soft-delete secret versions (marks deleted_at, data remains for undelete)
-- =============================================================================
CREATE OR REPLACE FUNCTION shared.vault_soft_delete_versions(
    p_secret_id     UUID,
    p_versions      INTEGER[]
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE shared.secret_versions
    SET deleted_at = now()
    WHERE secret_id = p_secret_id
      AND version = ANY(p_versions)
      AND deleted_at IS NULL
      AND destroyed = false;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Destroy secret versions (wipes ciphertext, irreversible)
-- =============================================================================
CREATE OR REPLACE FUNCTION shared.vault_destroy_versions(
    p_secret_id     UUID,
    p_versions      INTEGER[]
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE shared.secret_versions
    SET ciphertext = '',
        dek_id = '',
        destroyed = true,
        deleted_at = COALESCE(deleted_at, now())
    WHERE secret_id = p_secret_id
      AND version = ANY(p_versions)
      AND destroyed = false;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Expire leases: batch mark expired active leases
-- =============================================================================
CREATE OR REPLACE FUNCTION shared.vault_expire_leases(
    p_batch_size    INTEGER DEFAULT 1000
) RETURNS SETOF UUID AS $$
BEGIN
    RETURN QUERY
    UPDATE shared.leases
    SET state = 'expired'
    WHERE id IN (
        SELECT id FROM shared.leases
        WHERE state = 'active'
          AND expires_at < now()
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id;
END;
$$ LANGUAGE plpgsql;
