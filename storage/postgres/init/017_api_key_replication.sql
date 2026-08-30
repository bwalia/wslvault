-- 017_api_key_replication.sql
--
-- Replicate API keys across regions.
--
-- WHY
--   API keys lived only in the region that minted them. A key issued against
--   region A returned `key_not_found` on region B, so every operator, agent and
--   automation had to hold one credential per region — and a failover to the
--   peer region invalidated every login at once, silently, at the worst
--   possible moment.
--
--   Secrets, policies and tenants already replicate. API keys were the one
--   authentication input that did not, which made the mesh's two halves not
--   actually interchangeable.
--
-- WHAT IS REPLICATED
--   Only what `shared.api_keys` already stores: the SHA-256 *hash* of the key,
--   never the raw key (which exists only in the response to the mint call and
--   is unrecoverable afterwards). Replicating the hash is exactly as sensitive
--   as replicating the table, and the peer-facing replication API requires the
--   shared bearer token (services/replication-agent/src/auth.rs).
--
--   `last_used_at` is deliberately NOT part of the conflict key: it is
--   per-region telemetry, and letting it drive last-write-wins would make two
--   regions fight over a row on every authentication.

-- Allow the new event type.
ALTER TABLE system.replication_events
    DROP CONSTRAINT IF EXISTS replication_events_event_type_check;

ALTER TABLE system.replication_events
    ADD CONSTRAINT replication_events_event_type_check
    CHECK (event_type IN (
        'secret_upsert', 'secret_delete', 'secret_destroy',
        'key_rotate', 'policy_update', 'tenant_update',
        'region_failover', 'region_promote',
        'api_key_upsert'
    ));

-- =============================================================================
-- Trigger: emit api_key_upsert on create, rotate and revoke.
-- =============================================================================
CREATE OR REPLACE FUNCTION system.trg_emit_api_key_replication_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER   -- runs with definer's privileges so no BYPASSRLS is needed
AS $$
BEGIN
    -- Skip writes made BY the replication-agent, or region A and region B
    -- would bounce the same row back and forth forever.
    IF current_setting('app.replication_agent', true) = 'true' THEN
        RETURN NEW;
    END IF;

    -- last_used_at is updated on every authentication. Without this guard each
    -- login would emit a replication event, so a busy region would flood the
    -- outbox with rows that change nothing a peer needs.
    IF TG_OP = 'UPDATE'
       AND NEW.key_hash    IS NOT DISTINCT FROM OLD.key_hash
       AND NEW.policies    IS NOT DISTINCT FROM OLD.policies
       AND NEW.path_prefixes IS NOT DISTINCT FROM OLD.path_prefixes
       AND NEW.expires_at  IS NOT DISTINCT FROM OLD.expires_at
       AND NEW.revoked_at  IS NOT DISTINCT FROM OLD.revoked_at
       AND NEW.name        IS NOT DISTINCT FROM OLD.name
    THEN
        RETURN NEW;
    END IF;

    INSERT INTO system.replication_events
        (event_type, source_region, payload, vector_clock)
    VALUES (
        'api_key_upsert',
        system.current_region_id(),
        jsonb_build_object(
            'id',            NEW.id,
            'tenant_id',     NEW.tenant_id,
            'name',          NEW.name,
            -- bytea is not valid JSON; encode the hash for transport.
            'key_hash_b64',  encode(NEW.key_hash, 'base64'),
            'key_prefix',    NEW.key_prefix,
            'path_prefixes', NEW.path_prefixes,
            'policies',      NEW.policies,
            'created_by',    NEW.created_by,
            'created_at',    NEW.created_at,
            'expires_at',    NEW.expires_at,
            'revoked_at',    NEW.revoked_at,
            'rate_limit_per_minute', NEW.rate_limit_per_minute
        ),
        '{}'::jsonb
    );

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_api_keys_replication ON shared.api_keys;

CREATE TRIGGER trg_api_keys_replication
    AFTER INSERT OR UPDATE ON shared.api_keys
    FOR EACH ROW EXECUTE FUNCTION system.trg_emit_api_key_replication_event();
