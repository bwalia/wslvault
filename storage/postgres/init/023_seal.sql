-- WSLVault: persist the seal.
-- Migration: 023_seal.sql
--
-- ## What was missing
--
-- Everything. `grep -rniE '\bshamir\b|\bunseal\b|seal_status|\brekey\b'` across
-- the repository returned one hit, and it was a comment explaining what Shamir
-- sharing would be for. The root KEK was read from `VAULT_ROOT_KEY` — a
-- plaintext environment variable — and the process booted straight into an
-- unsealed state. Whoever could read a Kubernetes Secret, a Helm values file or
-- a process environment owned every secret in the vault, permanently, and there
-- was no documented recovery path if that value was lost.
--
-- ## What is stored here
--
-- Only the root key ENCRYPTED under an unseal key that is never stored at all.
-- The unseal key exists solely to protect the root key at rest; it is split
-- into shares at `sys/init` and reconstructed from a threshold of them at
-- `sys/unseal`.
--
-- So this table is worthless on its own. Reading it yields a ciphertext whose
-- key does not exist anywhere in the system — it exists only across the share
-- holders, and only `threshold` of them together can put it back.
--
-- Separating the two keys is also what makes rekeying possible later: shares
-- can be regenerated against a new unseal key without re-encrypting a single
-- tenant KEK, because the root key underneath never has to change.

CREATE TABLE IF NOT EXISTS system.seal_config (
    -- Singleton. A second row would mean a second root key, and every tenant
    -- KEK is encrypted under exactly one.
    id                SMALLINT     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    -- How many shares were issued, and how many are needed to unseal.
    shares            SMALLINT     NOT NULL CHECK (shares  >= 1),
    threshold         SMALLINT     NOT NULL CHECK (threshold >= 1),
    CONSTRAINT threshold_within_shares CHECK (threshold <= shares),
    -- base64(nonce || AES-256-GCM(root_key)) under the unseal key.
    sealed_root_key   TEXT         NOT NULL,
    -- Lets a reconstruction be checked before it is used, so a wrong set of
    -- shares reports as wrong shares rather than as a corrupt vault.
    unseal_key_check  TEXT         NOT NULL,
    initialized_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE system.seal_config IS
    'The sealed root key. Useless without a threshold of unseal shares, which are never stored.';
COMMENT ON COLUMN system.seal_config.sealed_root_key IS
    'Root key encrypted under the unseal key. The unseal key is not stored anywhere.';
