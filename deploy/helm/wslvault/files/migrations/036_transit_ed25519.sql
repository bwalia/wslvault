-- WSLVault: allow Ed25519 signing keys in system.key_descriptors.
-- Migration: 036_transit_ed25519.sql
--
-- ## Why
--
-- Transit `sign` was HMAC-SHA256 only: a shared-secret MAC that only a holder
-- of the key can check. A token issuer (opsapi, acting as the agent identity
-- provider - see docs/agent-identity.md) needs signatures that anyone can
-- verify from a published public key, while the private key stays inside the
-- vault and is never exported.
--
-- ## What is stored
--
-- Nothing new in shape. An Ed25519 private key is a 32-byte RFC 8032 seed, the
-- same size as an AES-256 key, so it is wrapped under the root KEK with the
-- same tenant:name:version AAD as every other transit key. Only the algorithm
-- label changes, and it is what keeps a signing seed from ever being loaded as
-- a cipher key (or the reverse).

ALTER TABLE system.key_descriptors
    DROP CONSTRAINT IF EXISTS key_descriptors_algorithm_check;

ALTER TABLE system.key_descriptors
    ADD CONSTRAINT key_descriptors_algorithm_check
    CHECK (algorithm IN ('aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305', 'ed25519'));
