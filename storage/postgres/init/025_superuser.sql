-- WSLVault: cross-tenant superuser access.
-- Migration: 025_superuser.sql
--
-- ## The problem this solves, and the one it creates
--
-- Every API key is bound to exactly one tenant, which is correct for normal
-- operation and leaves an operator with no way to administer the platform: no
-- way to inspect a tenant that has locked itself out, migrate data, or answer
-- "who has access to what" across the estate.
--
-- A superuser is a deliberate hole in the isolation this system otherwise
-- enforces everywhere. So it is built to be narrow and loud:
--
--   * **Granted, never asserted.** The flag lives in a signed token claim, is
--     stamped by identity-service alone, and is `false` on every identity
--     derived from a header. There is no request a caller can construct that
--     makes them a superuser.
--   * **Signed by the system key, not a tenant's.** Otherwise one tenant's
--     signing key could mint authority over all the others.
--   * **MFA is mandatory.** A stolen superuser key alone is not enough.
--   * **Audited on every use**, with the acting tenant recorded.
--   * **Short-lived**, because it is the highest-value credential in the system.

ALTER TABLE shared.api_keys
    ADD COLUMN IF NOT EXISTS is_superuser BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN shared.api_keys.is_superuser IS
    'Grants cross-tenant access. Requires MFA. Audited on every use.';

-- Superuser keys are rare and high-value; make them cheap to enumerate during
-- an access review. Anyone auditing this system will ask "who is a superuser"
-- first, and that question should not require a sequential scan.
CREATE INDEX IF NOT EXISTS idx_api_keys_superuser
    ON shared.api_keys (tenant_id, created_at)
    WHERE is_superuser AND revoked_at IS NULL;

-- Enforce the MFA requirement in the schema rather than only in application
-- code, so a key created by a future code path cannot skip it by omission.
ALTER TABLE shared.api_keys
    ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN shared.api_keys.mfa_required IS
    'Whether exchanging this key for a token requires a TOTP code. Always true for superuser keys.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'superuser_requires_mfa'
    ) THEN
        ALTER TABLE shared.api_keys
            ADD CONSTRAINT superuser_requires_mfa
            CHECK (NOT is_superuser OR mfa_required);
    END IF;
END $$;
