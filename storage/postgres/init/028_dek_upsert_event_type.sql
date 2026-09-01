-- 028_dek_upsert_event_type.sql
--
-- Allow the `dek_upsert` replication event.
--
-- WHY
--   Secrets replicate their ciphertext and dek_id to peer regions, but the
--   data-encryption key material did not, so a peer failed to decrypt a
--   replicated secret with "key not found". crypto-service now emits a
--   `dek_upsert` event when it mints a DEK, carrying that key wrapped under the
--   shared root key (see services/crypto-service kek_store). The event_type
--   CHECK constraint (last set in 017) did not list it, so every emit was
--   rejected by the database and silently dropped by the best-effort caller.
--
--   Additive to the 017 list; nothing else changes.

ALTER TABLE system.replication_events
    DROP CONSTRAINT IF EXISTS replication_events_event_type_check;

ALTER TABLE system.replication_events
    ADD CONSTRAINT replication_events_event_type_check
    CHECK (event_type IN (
        'secret_upsert', 'secret_delete', 'secret_destroy',
        'key_rotate', 'policy_update', 'tenant_update',
        'region_failover', 'region_promote',
        'api_key_upsert',
        'dek_upsert'
    ));
