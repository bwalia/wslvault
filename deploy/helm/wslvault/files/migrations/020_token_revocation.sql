-- WSLVault: durable token revocation.
-- Migration: 020_token_revocation.sql
--
-- ## What was wrong
--
-- Revocation was `Arc<RwLock<HashSet<String>>>` in identity-service. Three
-- consequences, all of which made "revoke this token" a lie:
--
--   1. It lived in one process. The Helm chart runs two replicas, so revoking
--      on pod A left the token working on pod B.
--   2. It did not survive a restart. A rolling deploy un-revoked every token.
--   3. Nothing evicted entries, so the set grew without bound for the lifetime
--      of the process.
--
-- It was also never consulted by secret-engine at all, so a revoked token kept
-- working against the KV v2 mount regardless.
--
-- ## Design
--
-- Store the SHA-256 of the token, never the token itself: this table is a
-- credential store otherwise, and a database backup would hand over live
-- tokens. A hash is sufficient — revocation only ever asks "is this exact
-- token revoked", never "list the revoked tokens".
--
-- `expires_at` carries the token's own `exp` claim so rows can be reaped once
-- the token would have expired anyway. A revocation is only meaningful up to
-- that point; past it the JWT validator rejects the token on its own.

CREATE TABLE IF NOT EXISTS system.revoked_tokens (
    -- SHA-256 of the raw token string, hex-encoded (64 chars).
    token_hash   CHAR(64)     PRIMARY KEY,
    -- Tenant the token belonged to, for operator forensics. Not a foreign key:
    -- revocations must outlive tenant deletion.
    tenant_id    TEXT         NOT NULL DEFAULT '',
    -- Principal the token was issued to, for "revoke everything for this user".
    principal_id TEXT         NOT NULL DEFAULT '',
    -- The token's own exp claim. Rows are reapable after this instant.
    expires_at   TIMESTAMPTZ  NOT NULL,
    revoked_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Supports the reaper's range delete.
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at
    ON system.revoked_tokens (expires_at);

-- Supports revoke-by-principal.
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_principal
    ON system.revoked_tokens (tenant_id, principal_id);

COMMENT ON TABLE system.revoked_tokens IS
    'Tokens revoked before their natural expiry. Stores SHA-256 hashes, never raw tokens.';

-- Delete revocations for tokens that have expired on their own. Safe to run
-- from any replica, on any schedule; returns the number of rows reaped.
CREATE OR REPLACE FUNCTION system.reap_expired_revocations()
    RETURNS bigint
    LANGUAGE plpgsql
AS $$
DECLARE
    reaped bigint;
BEGIN
    DELETE FROM system.revoked_tokens WHERE expires_at < now();
    GET DIAGNOSTICS reaped = ROW_COUNT;
    RETURN reaped;
END;
$$;
