/**
 * How a set of recovery codes is written down.
 *
 * Codes are scoped to the single API key they were issued to — the server looks
 * them up by `api_key_id`, so a code from one account is simply not present for
 * another. Eight strings of base32 on their own do not say which account that
 * is, and the failure mode is silent: a user in two organisations tries the
 * wrong set, gets "invalid or already-used code", and reasonably concludes the
 * codes are broken rather than mismatched. Every attempt also spends a
 * single-use login challenge.
 *
 * So the account name travels with the codes — on screen, in what gets copied,
 * and in the downloaded file. Both places that issue codes use this, so the two
 * cannot drift apart.
 */
export function recoveryCodeDocument(
  account: string | undefined,
  codes: readonly string[],
  issuedAt = new Date(),
): string {
  const who = account?.trim() || 'your WSLVault account'
  return [
    `WSLVault backup codes — ${who}`,
    `Issued ${issuedAt.toISOString().slice(0, 10)}`,
    '',
    `These work only for ${who}. They will not sign you in to any other`,
    'account, even one of yours.',
    '',
    'Each code works once. Store them where you can reach them without',
    'this vault — and without the phone they replace.',
    '',
    ...codes,
    '',
  ].join('\n')
}

/**
 * A human-checkable label for the key a set of codes belongs to.
 *
 * `wslv_hFy0JBrP…` → `key hFy0JBrP`. The eight characters after the prefix are
 * the same `key_prefix` the server stores, so this names exactly the key the
 * codes are scoped to — without a round trip, and without ever putting the
 * secret part of the key anywhere it might be written down.
 *
 * Used where the tenant's own name is not to hand. Where it is (the invitation
 * wizard knows it), pass that instead: "Riyan Ltd" beats "key hFy0JBrP" for
 * someone deciding which envelope to open.
 */
export function keyLabel(apiKey: string): string | undefined {
  const prefix = apiKey.trim().replace(/^wslv_/, '').slice(0, 8)
  return prefix.length === 8 ? `key ${prefix}` : undefined
}

/**
 * Filename for the download.
 *
 * Named after the account for the same reason as the header, plus a practical
 * one: a second download of `wslvault-recovery-codes.txt` lands beside the
 * first as `... (1).txt`, and the browser will not say which is which.
 */
export function recoveryCodeFilename(account: string | undefined): string {
  const slug = (account ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
  return slug ? `wslvault-backup-codes-${slug}.txt` : 'wslvault-backup-codes.txt'
}
