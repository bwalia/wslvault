#!/usr/bin/env node
// WSLVault Secret Lifecycle Example — Node.js (built-in fetch, Node 18+)
//
// Shows the full flow:
//   1. Write a secret (base64-encoded payload)
//   2. Read the secret back and decode it
//   3. List secrets
//   4. Read a specific version
//   5. Soft-delete a version
//   6. (Optional) Exchange an API key for a JWT via /v1/auth/api-key
//
// Usage:
//   VAULT_ADDR=http://localhost:8081 \
//   VAULT_IDENTITY_ADDR=http://localhost:18082 \
//   VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d \
//   node wslvault_example.js

'use strict';

const VAULT_ADDR = process.env.VAULT_ADDR ?? 'http://localhost:8081';
const VAULT_IDENTITY_ADDR = process.env.VAULT_IDENTITY_ADDR ?? 'http://localhost:18082';
const VAULT_TENANT_ID = process.env.VAULT_TENANT_ID ?? '019d813d-74bc-7660-89a7-f02fd9f2736d';
const VAULT_PRINCIPAL_ID = process.env.VAULT_PRINCIPAL_ID ?? 'nodejs-example';
const VAULT_POLICIES = process.env.VAULT_POLICIES ?? 'admin';

const SECRET_PATH = 'demo/nodejs/api-key';

// In production the gateway injects X-Principal-Id / X-Policies from the JWT.
// When calling the secret-engine directly (dev / service mesh), pass them manually.
const vaultHeaders = {
  'Content-Type': 'application/json',
  'X-Tenant-Id': VAULT_TENANT_ID,
  'X-Principal-Id': VAULT_PRINCIPAL_ID,
  'X-Policies': VAULT_POLICIES,
};

// Optional: exchange an API key for a JWT
//
// async function authenticate(apiKey) {
//   const resp = await fetch(`${VAULT_IDENTITY_ADDR}/v1/auth/api-key`, {
//     method: 'POST',
//     headers: { 'Content-Type': 'application/json' },
//     body: JSON.stringify({ api_key: apiKey, tenant_id: VAULT_TENANT_ID }),
//   });
//   const { token } = await resp.json();
//   return token; // Use as: 'Authorization': `Bearer ${token}`
// }

/** Throw a descriptive error when the HTTP response signals failure. */
async function assertOk(resp, context) {
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`${context}: HTTP ${resp.status} — ${body}`);
  }
  return resp;
}

async function main() {
  // ── 1. Write a secret ──────────────────────────────────────────────────────
  console.log(`==> 1. Writing secret to '${SECRET_PATH}'...`);
  const secretPayload = { api_key: 'sk-1234567890abcdef', service: 'openai', tier: 'premium' };
  // WSLVault stores opaque bytes — base64-encode the JSON payload.
  const data = Buffer.from(JSON.stringify(secretPayload)).toString('base64');

  const writeResp = await fetch(`${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}`, {
    method: 'POST',
    headers: vaultHeaders,
    body: JSON.stringify({ data }),
  });
  await assertOk(writeResp, 'write secret');
  const writeBody = await writeResp.json();
  console.log(`    secret_id=${writeBody.secret_id}  version=${writeBody.version}`);
  const version = writeBody.version;

  // ── 2. Read the secret back ────────────────────────────────────────────────
  console.log(`\n==> 2. Reading secret from '${SECRET_PATH}'...`);
  const readResp = await fetch(`${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}`, {
    headers: vaultHeaders,
  });
  await assertOk(readResp, 'read secret');
  const readBody = await readResp.json();
  const decoded = JSON.parse(Buffer.from(readBody.data, 'base64').toString('utf-8'));
  console.log('    Decoded:', decoded);

  // ── 3. List secrets ────────────────────────────────────────────────────────
  console.log('\n==> 3. Listing secrets...');
  const listResp = await fetch(`${VAULT_ADDR}/v1/secret/list`, { headers: vaultHeaders });
  await assertOk(listResp, 'list secrets');
  console.log('    Secrets:', await listResp.json());

  // ── 4. Read a specific version ─────────────────────────────────────────────
  console.log(`\n==> 4. Reading version ${version} explicitly...`);
  const verResp = await fetch(
    `${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}?version=${version}`,
    { headers: vaultHeaders },
  );
  await assertOk(verResp, 'read version');
  const verBody = await verResp.json();
  console.log(`    version=${verBody.version}  created_at=${verBody.created_at}`);

  // ── 5. Soft-delete the version ─────────────────────────────────────────────
  console.log(`\n==> 5. Soft-deleting version ${version}...`);
  const delResp = await fetch(`${VAULT_ADDR}/v1/secret/delete/${SECRET_PATH}`, {
    method: 'POST',
    headers: vaultHeaders,
    body: JSON.stringify({ versions: [version] }),
  });
  await assertOk(delResp, 'delete secret');
  console.log('    Deleted (soft — data retained for undelete).');

  console.log('\nDone! All WSLVault operations completed successfully.');
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
