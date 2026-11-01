# Transit signing keys (Ed25519) and versioned HMAC

Transit can hold **Ed25519** keys for public-key signatures alongside the
**AES-256-GCM** keys it has always had. The private key never leaves the
service: callers ask transit to sign, and anyone can verify against the
published public keys. This is how an external token issuer, such as opsapi
acting as the agent identity provider (see
[`../agent-identity.md`](../agent-identity.md)), signs JWTs without holding a
signing key.

## Create a signing key

```bash
curl -sX POST "$VAULT_ADDR/v1/transit/keys/agent-idp" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"type":"ed25519"}'
# → {"key_name":"agent-idp","algorithm":"ed25519"}
```

Omitting the body creates an AES-256-GCM key, as before. An unknown `type` is
rejected; it never falls back to AES.

## Sign

```bash
curl -sX POST "$VAULT_ADDR/v1/transit/sign/agent-idp" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"data\":\"$(printf %s "$SIGNING_INPUT" | base64)\"}"
# → {"signature":"vault:v1:n7P3…p4Ag","key_version":1,"kid":"agent-idp:v1","algorithm":"EdDSA"}
```

- The part of `signature` after the last `:` is the raw 64-byte signature in
  base64url without padding. That is the third segment of a compact JWS, so
  a JWT is `base64url(header).base64url(claims).<that part>`, with
  `"alg":"EdDSA"` and `"kid":"agent-idp:v1"` in the header.
- `key_version` (optional in the request) signs with an older version. Leave
  it out to use the current version.
- For an **AES key**, `sign` and `verify` keep their old behaviour: a hex
  HMAC-SHA256 with no extra fields.

## Publish the public keys (JWKS)

```bash
curl -s "$VAULT_ADDR/v1/transit/keys/agent-idp/public" -H "Authorization: Bearer $TOKEN"
# → {"keys":[{"kty":"OKP","crv":"Ed25519","x":"sCZ6…ySw","kid":"agent-idp:v1","use":"sig","alg":"EdDSA"}]}
```

Every version is listed, so a token signed just before a rotation still
verifies. An identity provider serves this document, or a cached copy, as its
`jwks_uri`. It contains no private material.

## Verify

`POST /v1/transit/verify/:key` with `{"data","signature"}` takes the
`vault:v{N}:…` form and checks it against version N. It answers
`{"valid":true|false}` and nothing more.

## Rotate

`POST /v1/transit/keys/:key/rotate` adds a version of the **same algorithm**.
New signatures use it. Old versions keep verifying and stay in the JWKS. To
recover from a compromised key: rotate, wait out the longest token lifetime
signed under the old version, then retire it.

## Versioned HMAC

```bash
curl -sX POST "$VAULT_ADDR/v1/transit/hmac/agent-secret" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"data\":\"$(printf %s "$SECRET" | base64)\"}"
# → {"hmac":"vault:v1:17c9…a6d7","key_version":1}
```

AES keys only. Store the `hmac` and recompute it with `key_version` set to
check a presented secret later. The stored value then stays checkable across
rotations, which the unversioned `sign` cannot do. opsapi uses this to verify
agent secrets without the HMAC key ever leaving wslvault.

## Rules the service enforces

| Operation | aes256-gcm | ed25519 |
|---|---|---|
| encrypt / decrypt / rewrap | yes | **refused** (400) |
| hmac | yes | **refused** (400) |
| sign / verify | HMAC-SHA256 (hex) | Ed25519 (`vault:vN:` base64url) |
| keys/:key/public | **refused** (400) | JWKS |

An Ed25519 seed and an AES key are both 32 bytes. These refusals keep a
signing key from ever being used as a cipher key.

## Policy resources

`transit/sign/<key>` (write), `transit/verify/<key>` (read),
`transit/hmac/<key>` (write), `transit/keys/<key>` (write, to create), and
`transit/keys/<key>/public` (read). The default `transit/**` tenant policy
covers them all. For an identity provider's service identity, grant only
`transit/sign/agent-idp`, `transit/keys/agent-idp/public` and
`transit/hmac/agent-secret`.

## Upgrading

Two migrations are required before creating keys:

- `036_transit_ed25519.sql` allows the `ed25519` algorithm label.
- `037_transit_multiple_keys_per_tenant.sql` fixes an older bug: with the
  PostgreSQL backend, a tenant's **second** transit key failed with
  `idx_key_descriptors_kek_unique`. This affected AES keys too.
