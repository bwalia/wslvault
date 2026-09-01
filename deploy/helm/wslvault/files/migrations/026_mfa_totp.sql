-- WSLVault: authenticator-app (TOTP) second factor.
-- Migration: 026_mfa_totp.sql
--
-- ## Why
--
-- Authentication was a single factor: possession of an API key. A key that
-- leaks — in a CI log, a screenshot, a git history — is a complete
-- authentication bypass with nothing standing behind it.
--
-- TOTP (RFC 6238) adds a factor the holder must produce live from a device,
-- so a leaked key alone stops being enough.
--
-- ## Who it applies to
--
-- Interactive logins and, always, the superuser. Machine keys — the External
-- Secrets Operator, CI, the SDKs — are exempt by default, because a service
-- account cannot read an authenticator app and forcing it would break every
-- non-interactive integration the day it shipped. The exemption is explicit
-- per key (`api_keys.mfa_required`), not a global setting somebody can forget
-- they turned off.
--
-- ## What is stored
--
-- The TOTP secret is wrapped by the crypto-service before it is written, so it
-- sits under the root KEK and therefore under the seal — the same custody as
-- every other piece of key material here. A database dump does not yield
-- anyone's second factor.
--
-- `last_used_step` is the replay defence. A TOTP code is valid for a whole
-- 30-second window, so without it an attacker who observes a code — over the
-- shoulder, in a phishing proxy — can reuse it for the rest of that window.
-- Recording the last accepted step makes each code single-use.

CREATE TABLE IF NOT EXISTS shared.mfa_totp (
    -- The API key this enrolment protects.
    api_key_id      UUID         PRIMARY KEY
                                 REFERENCES shared.api_keys(id) ON DELETE CASCADE,
    tenant_id       UUID         NOT NULL REFERENCES system.tenants(id),
    -- TOTP secret, wrapped by the crypto-service as "<dek_id>:<b64>".
    wrapped_secret  TEXT         NOT NULL,
    -- Highest TOTP step already accepted. A code at or below this is a replay.
    last_used_step  BIGINT       NOT NULL DEFAULT 0,
    -- Enrolment is two-phase: a secret is issued, then confirmed by proving a
    -- code from it. Unconfirmed enrolments never satisfy a challenge, so a
    -- half-finished enrolment cannot lock anyone out OR let anyone in.
    confirmed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE shared.mfa_totp IS
    'TOTP enrolments. Secrets are wrapped under the root KEK; last_used_step makes each code single-use.';

CREATE INDEX IF NOT EXISTS idx_mfa_totp_tenant ON shared.mfa_totp (tenant_id);

ALTER TABLE shared.mfa_totp ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_totp ON shared.mfa_totp;
CREATE POLICY tenant_isolation_mfa_totp ON shared.mfa_totp
    USING (shared.rls_tenant_visible(tenant_id));

-- =============================================================================
-- Recovery codes
-- =============================================================================
-- Without these, losing a phone means losing the account — and in a vault that
-- means losing access to every secret the key could read. Stored as hashes for
-- the same reason API keys are: this table must not be a credential store.

CREATE TABLE IF NOT EXISTS shared.mfa_recovery_codes (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id   UUID        NOT NULL REFERENCES shared.api_keys(id) ON DELETE CASCADE,
    tenant_id    UUID        NOT NULL REFERENCES system.tenants(id),
    -- SHA-256 of the code, hex. Never the code itself.
    code_hash    CHAR(64)    NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (api_key_id, code_hash)
);

COMMENT ON TABLE shared.mfa_recovery_codes IS
    'Single-use fallbacks for a lost authenticator. Hashed, and burned on use.';

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_unused
    ON shared.mfa_recovery_codes (api_key_id)
    WHERE used_at IS NULL;

ALTER TABLE shared.mfa_recovery_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_recovery ON shared.mfa_recovery_codes;
CREATE POLICY tenant_isolation_mfa_recovery ON shared.mfa_recovery_codes
    USING (shared.rls_tenant_visible(tenant_id));
