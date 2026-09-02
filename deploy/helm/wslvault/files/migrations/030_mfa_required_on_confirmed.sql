-- WSLVault: demand a code from keys that already have a confirmed authenticator.
-- Migration: 030_mfa_required_on_confirmed.sql
--
-- ## Why
--
-- Confirming an enrolment used to mark `shared.mfa_totp.confirmed_at` and leave
-- `shared.api_keys.mfa_required` untouched. Login only consults the flag, so a
-- finished enrolment was decorative: the holder was told a code would be asked
-- for, and the bare key still signed in.
--
-- `mfa_store::confirm` now writes both in one transaction. This statement is
-- the backfill for anyone who enrolled under the old code — re-enrolment is
-- refused once `confirmed_at` is set, so those keys would otherwise stay
-- unprotected forever.

UPDATE shared.api_keys k
SET mfa_required = true
FROM shared.mfa_totp t
WHERE t.api_key_id = k.id
  AND t.confirmed_at IS NOT NULL
  AND NOT k.mfa_required;
