-- WSLVault: make the audit log tamper-evident, not merely signed.
-- Migration: 022_audit_hash_chain.sql
--
-- ## What was wrong
--
-- Every record was HMAC-signed independently over its own fields and nothing
-- else. That detects an edit to a row, and nothing else:
--
--   * Deleting a row is undetectable — the survivors still verify.
--   * Truncating the log is undetectable, for the same reason.
--   * Reordering is undetectable — there was no sequence to compare against.
--
-- An attacker who can reach the table can therefore remove the evidence of
-- what they did, which is the one thing an audit log exists to prevent. The
-- signature was also never checked: `verify_signature` was `#[cfg(test)]`.
--
-- ## The chain
--
-- Each record now carries a per-tenant sequence number and the signature of
-- its predecessor. The signature covers the record's own fields AND
-- `prev_hash`, so every record transitively commits to the entire history
-- before it. Removing or reordering any record breaks verification at that
-- point and at every point after it.
--
-- The chain is per-tenant: tenants are isolated everywhere else, and a shared
-- chain would let one tenant's write volume affect another's verification.
--
-- ## Concurrency
--
-- Appends take a transaction-scoped advisory lock keyed on the tenant, so two
-- concurrent writers cannot read the same tip and fork the chain. The lock is
-- per-tenant, so tenants do not serialise against each other.
--
-- ponytail: one advisory lock per tenant serialises that tenant's audit
-- appends. Fine at expected volume; if a single tenant's audit rate ever
-- becomes the bottleneck, shard the chain by (tenant, day) and verify per
-- shard.

ALTER TABLE shared.audit_events
    ADD COLUMN IF NOT EXISTS seq       BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT;

COMMENT ON COLUMN shared.audit_events.seq IS
    'Per-tenant monotonic sequence. Gaps or repeats mean records were removed or the chain forked.';
COMMENT ON COLUMN shared.audit_events.prev_hash IS
    'Signature of the preceding record in this tenant''s chain; empty string for the genesis record.';

-- Finding a tenant's chain tip is the hot path on every append.
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_seq
    ON shared.audit_events (tenant_id, seq DESC);

-- Returns the current chain tip for a tenant: its sequence number and the
-- signature that the next record must commit to.
--
-- Callers MUST hold the tenant's advisory lock across this and the subsequent
-- insert, or two appends can read the same tip.
CREATE OR REPLACE FUNCTION shared.audit_chain_tip(p_tenant_id uuid)
    RETURNS TABLE (tip_seq bigint, tip_signature text)
    LANGUAGE sql STABLE
AS $$
    SELECT coalesce(seq, 0), coalesce(signature, '')
    FROM shared.audit_events
    WHERE tenant_id = p_tenant_id AND seq IS NOT NULL
    ORDER BY seq DESC
    LIMIT 1;
$$;

-- Report breaks in a tenant's chain: a gap in the sequence, or a record whose
-- prev_hash does not match its predecessor's signature.
--
-- This finds structural damage without needing the HMAC key. Verifying the
-- signatures themselves requires the key and happens in the service.
CREATE OR REPLACE FUNCTION shared.audit_chain_breaks(p_tenant_id uuid)
    RETURNS TABLE (at_seq bigint, reason text)
    LANGUAGE sql STABLE
AS $$
    WITH ordered AS (
        SELECT seq, signature, prev_hash,
               lag(seq)       OVER (ORDER BY seq) AS prior_seq,
               lag(signature) OVER (ORDER BY seq) AS prior_signature
        FROM shared.audit_events
        WHERE tenant_id = p_tenant_id AND seq IS NOT NULL
    )
    SELECT seq,
           CASE
               WHEN prior_seq IS NOT NULL AND seq <> prior_seq + 1
                   THEN 'sequence gap: records are missing'
               ELSE 'prev_hash does not match the preceding record'
           END
    FROM ordered
    WHERE (prior_seq IS NOT NULL AND seq <> prior_seq + 1)
       OR (prior_signature IS NOT NULL AND prev_hash IS DISTINCT FROM prior_signature);
$$;
