-- WSLVault: name platform administration explicitly, so the chart can stop
-- pinning VAULT_ADMIN_POLICY to "admin".
-- Migration: 033_platform_admin_policy.sql
--
-- ## Why
--
-- `DEFAULT_ADMIN_POLICY` is `wslvault:platform-admin`, but no key ever carried
-- it, so the chart pinned `adminPolicy: "admin"` to keep the dashboard working.
-- That made *any* key holding a policy named `admin` a platform administrator
-- over every tenant — and `admin` is the single most likely name a tenant gives
-- its own administrators. A tenant that created an `admin` policy for its own
-- staff was silently handing them the estate.
--
-- ## What this does
--
-- Grants `wslvault:platform-admin` to the keys that are genuinely operator
-- credentials: those carrying `root`, and existing superusers. Those keys
-- already have platform authority in practice, so this grants nothing new —
-- it names what they already are, under the policy the code actually checks.
--
-- Keys carrying only `admin` are deliberately NOT included. They are the ones
-- the pin over-privileged, and removing that is the point of the exercise.
--
-- ## Ordering
--
-- This must land BEFORE `identityService.adminPolicy` is cleared in the chart.
-- Reversed, every operator is locked out of key and tenant management until it
-- runs. Both changes are in the same commit for that reason.
--
-- An operator who finds themselves without access after this can restore it
-- with the bootstrap token (X-Admin-Token), which is not policy-gated.

UPDATE shared.api_keys
SET policies = array_append(policies, 'wslvault:platform-admin')
WHERE revoked_at IS NULL
  AND NOT ('wslvault:platform-admin' = ANY(policies))
  AND ('root' = ANY(policies) OR is_superuser);
