-- WSLVault: a distinct token-signing keypair per tenant.
-- Migration: 024_tenant_signing_keys.sql
--
-- ## What was wrong
--
-- Every token in the system was an HS256 JWT signed with one shared
-- `VAULT_JWT_SECRET`. Two consequences:
--
--   1. **Any service that could verify a token could also mint one.**
--      secret-engine holds the secret in order to check KV v2 callers, so
--      compromising secret-engine yielded the ability to forge a token for any
--      principal in any tenant. Symmetric MACs cannot separate those roles.
--
--   2. **One key covered every tenant.** There was no cryptographic boundary
--      between tenants at the token layer at all — only the `tenant_id` claim,
--      protected by the same key everyone already had.
--
-- ## What replaces it
--
-- An Ed25519 keypair per tenant. identity-service holds the private keys and is
-- the only thing that can sign; every other service fetches public keys from
-- the JWKS endpoint and can only verify. A leaked verifier forges nothing, and
-- a leaked tenant key signs for that tenant alone.
--
-- ## Custody
--
-- Private keys are stored wrapped by the crypto-service, which means they are
-- protected by the root KEK and therefore by the seal. A sealed vault cannot
-- unwrap a signing key, so it cannot mint tokens — which is the correct
-- behaviour, and follows for free rather than being special-cased.
--
-- The public half is stored in the clear: that is what a JWKS endpoint serves.

CREATE TABLE IF NOT EXISTS system.tenant_signing_keys (
    -- JWT `kid`. Verifiers select a key by this, so it must be stable and
    -- unique across the deployment.
    kid              TEXT         PRIMARY KEY,
    -- Owning tenant. NULL is reserved for the system key that signs superuser
    -- tokens, which by definition are not bound to one tenant.
    tenant_id        UUID         REFERENCES system.tenants(id),
    algorithm        TEXT         NOT NULL DEFAULT 'EdDSA' CHECK (algorithm = 'EdDSA'),
    -- base64url, unpadded: the `x` parameter of an OKP/Ed25519 JWK.
    public_key       TEXT         NOT NULL,
    -- PKCS#8 private key, wrapped by the crypto-service as "<dek_id>:<b64>".
    wrapped_private_key TEXT      NOT NULL,
    state            TEXT         NOT NULL DEFAULT 'active'
                                  CHECK (state IN ('active', 'rotating_out', 'retired')),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    retired_at       TIMESTAMPTZ
);

COMMENT ON TABLE system.tenant_signing_keys IS
    'Per-tenant Ed25519 token signing keys. Private halves are wrapped under the root KEK, so a sealed vault cannot mint tokens.';
COMMENT ON COLUMN system.tenant_signing_keys.tenant_id IS
    'NULL for the system key that signs cross-tenant superuser tokens.';

-- Signing looks up "this tenant's active key" on every token issued.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_signing_keys_active
    ON system.tenant_signing_keys (tenant_id)
    WHERE state = 'active' AND tenant_id IS NOT NULL;

-- Exactly one active system key, for superuser tokens.
CREATE UNIQUE INDEX IF NOT EXISTS uq_system_signing_key_active
    ON system.tenant_signing_keys ((tenant_id IS NULL))
    WHERE state = 'active' AND tenant_id IS NULL;

-- JWKS serves every key a live token might have been signed with, so retired
-- keys drop out but rotating_out ones stay until their tokens expire.
CREATE INDEX IF NOT EXISTS idx_tenant_signing_keys_publishable
    ON system.tenant_signing_keys (state)
    WHERE state IN ('active', 'rotating_out');
