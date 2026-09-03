-- WSLVault: one-time, expiring invitations for onboarding a tenant's first user.
-- Migration: 031_tenant_invitations.sql
--
-- ## Why
--
-- Creating a tenant produced an empty shell: a row in system.tenants with no
-- API key, and no way for anyone at that organisation to obtain one. The only
-- route in was for an operator to mint a key themselves and hand it over out of
-- band. This table is the missing link — an operator invites an address, and
-- the recipient mints their own first key by redeeming it.
--
-- ## What is stored
--
-- Only the SHA-256 of the token, hex-encoded — never the token. An invitation
-- is a bearer credential: whoever holds it can obtain a working API key for the
-- tenant, so the table would otherwise be a credential store and a database
-- dump would hand over live access. The same reasoning already governs
-- shared.api_keys and shared.mfa_recovery_codes.
--
-- ## Single use, and why the constraint lives here
--
-- `used_at` is set by the redeeming UPDATE itself, guarded by
-- `WHERE used_at IS NULL`. Two requests presenting the same token race: both
-- read NULL, and a check-then-write in the application would let both mint a
-- key. Here the second UPDATE matches no row and the caller is told the
-- invitation is spent. The same argument as shared.mfa_totp.last_used_step.

CREATE TABLE IF NOT EXISTS shared.tenant_invitations (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES system.tenants (id) ON DELETE CASCADE,

    -- Where the invitation was sent. Kept so an operator can see who was
    -- invited and re-send, and so the minted key can be named after a person
    -- rather than "key-3".
    email        TEXT NOT NULL,

    -- Hex SHA-256 of the raw token. UNIQUE because redemption looks the
    -- invitation up by this value.
    token_hash   TEXT NOT NULL UNIQUE,

    -- Policies the redeemed key will carry. An invitation therefore decides the
    -- recipient's authority up front, at the moment an operator who understands
    -- it makes the decision — not at redemption by the recipient.
    policies     TEXT[] NOT NULL DEFAULT ARRAY['default'],

    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,

    -- NULL until redeemed. Set once, never cleared: a spent invitation stays
    -- spent, and the row is evidence of when access was granted.
    used_at      TIMESTAMPTZ,

    -- The key minted on redemption, for the audit trail. ON DELETE SET NULL so
    -- revoking the key does not erase the record that the invitation was used.
    api_key_id   UUID REFERENCES shared.api_keys (id) ON DELETE SET NULL,

    CONSTRAINT tenant_invitations_expiry_after_creation
        CHECK (expires_at > created_at)
);

COMMENT ON TABLE shared.tenant_invitations IS
    'One-time, expiring invitations. Redeeming one mints the recipient''s first API key.';
COMMENT ON COLUMN shared.tenant_invitations.token_hash IS
    'Hex SHA-256 of the invitation token. The token itself is never stored.';
COMMENT ON COLUMN shared.tenant_invitations.used_at IS
    'Set by the redeeming UPDATE under WHERE used_at IS NULL — that is what makes redemption single-use.';

-- Redemption is the hot path and looks up by hash alone.
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_token_hash
    ON shared.tenant_invitations (token_hash);

-- "What is outstanding for this tenant?" — the operator's view.
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_pending
    ON shared.tenant_invitations (tenant_id, expires_at)
    WHERE used_at IS NULL;

-- Tenant-scoped like every other table here. Declared now so enabling
-- enforcement later (029) does not need to revisit this one; it is inert while
-- the application connects as the table owner.
ALTER TABLE shared.tenant_invitations ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'shared'
          AND tablename = 'tenant_invitations'
          AND policyname = 'tenant_invitations_isolation'
    ) THEN
        CREATE POLICY tenant_invitations_isolation ON shared.tenant_invitations
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
    END IF;
END $$;

-- Redemption looks an invitation up by token BEFORE any tenant scope is known —
-- the whole point is that the recipient has no session yet. That read therefore
-- runs outside the policy above, which is why the lookup is by unguessable
-- 256-bit token rather than by anything a caller could enumerate.

-- Expired and spent invitations are not needed forever. Reaped rather than
-- kept: an expired invitation is inert, and the audit log already records the
-- grant. Retains used rows for 90 days so "how did this key come to exist?"
-- stays answerable.
CREATE OR REPLACE FUNCTION shared.reap_expired_invitations()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    removed BIGINT;
BEGIN
    DELETE FROM shared.tenant_invitations
    WHERE (used_at IS NULL AND expires_at < now() - INTERVAL '7 days')
       OR (used_at IS NOT NULL AND used_at < now() - INTERVAL '90 days');
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

COMMENT ON FUNCTION shared.reap_expired_invitations() IS
    'Delete long-expired unused invitations and redemption records older than 90 days.';
