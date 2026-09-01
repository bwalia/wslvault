# Signing in, and onboarding a tenant

Three roles, and keeping them distinct is the whole point:

| Role | Credential | Can do |
|---|---|---|
| **Platform operator** | `VAULT_ADMIN_TOKEN` (env), or a token with `wslvault:platform-admin`, or any superuser token | Create and delete tenants; manage any tenant's API keys |
| **Superuser** | An API key with `is_superuser` — **always** requires MFA | Everything a platform operator can, plus read/write across tenants |
| **Tenant user** | An API key in one tenant | Only that tenant's secrets, subject to policy |

A tenant's own `admin` policy is **not** platform administration. That
distinction is enforced: the platform policy is named `wslvault:platform-admin`
precisely so a tenant naming its own policy `admin` does not inherit the estate.

## The chicken and egg

You cannot sign in before a tenant exists, and you cannot create a tenant
without a credential. `VAULT_ADMIN_TOKEN` breaks the cycle — it is the only
credential that exists before anything else does.

```bash
# Set on identity-service, from your secret manager.
VAULT_ADMIN_TOKEN=$(openssl rand -base64 32)
```

Treat it as a break-glass credential: it bypasses MFA and answers to no tenant.
Once you have a superuser key with an authenticator on it, prefer that and keep
the bootstrap token for recovery.

## 1. Create the tenant

```bash
curl -sX POST localhost:8082/v1/tenants \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"initech","display_name":"Initech Ltd","tier":"shared",
       "root_key_id":"initech-kek"}'
```

`slug` is lowercase, alphanumeric and hyphens. Keep the returned `id` — it is
the `tenant_id` everything else takes.

## 2. Create the tenant's first key

```bash
curl -sX POST localhost:8082/v1/api-keys \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"bob","tenant_id":"<id>","policies":["admin"],"mfa_required":true}'
```

| Field | Meaning |
|---|---|
| `policies` | Policy **names**. Nothing is granted until a document by that name exists — see step 5. |
| `mfa_required` | `true` for people, omit for machines. A service account cannot read an authenticator app. |
| `is_superuser` | Cross-tenant access. Forces `mfa_required` on; the schema enforces it. |

The `key` in the response is shown **once**.

## 3. Enrol the authenticator

Any RFC 6238 app: Google Authenticator, Microsoft Authenticator, 1Password,
Bitwarden, Authy, FreeOTP. There is nothing to choose — enrolment returns a
standard `otpauth://` URI (SHA-1, 6 digits, 30s), which all of them expect.

```bash
curl -sX POST localhost:8082/v1/auth/mfa/totp/enroll \
  -H 'Content-Type: application/json' -d '{"api_key":"wslv_…"}'
```

| Returned | Do this with it |
|---|---|
| `otpauth_uri` | Render as a QR code and scan it |
| `secret` | Type into the app manually if you cannot scan |
| `recovery_codes` | Eight single-use fallbacks — **shown once**, stored only as hashes |

```bash
# Render the QR locally. Do NOT paste the URI into an online generator:
# it contains the secret.
qrencode -t ANSIUTF8 "otpauth://totp/WSLVault:…"
```

Then prove it works. Until this succeeds the enrolment is inert — it neither
satisfies a login nor blocks one, so a half-finished enrolment is harmless:

```bash
curl -sX POST localhost:8082/v1/auth/mfa/totp/confirm \
  -H 'Content-Type: application/json' -d '{"api_key":"wslv_…","code":"123456"}'
```

## 4. Sign in

**In the UI:** enter the API key, then the 6-digit code. Recovery codes go in
the same field.

**On the API**, two steps:

```bash
curl -sX POST localhost:8082/v1/auth/api-key -d '{"api_key":"wslv_…"}'
# → {"mfa_required":true,"challenge":"…","expires_in_seconds":120}

curl -sX POST localhost:8082/v1/auth/mfa/totp \
     -d '{"challenge":"…","code":"123456"}'
# → {"token":"…","tenant_id":"…","policies":[…],"expires_at":"…"}
```

Machine keys skip the second step entirely — `POST /v1/auth/api-key` returns a
token directly. That is why ESO, CI and the SDKs keep working unchanged.

The challenge is single-use and expires in two minutes, so a wrong code costs a
fresh login rather than allowing repeated guesses against one challenge.

## 5. Grant the tenant something

A key carries policy *names*; a fresh tenant grants nothing until the documents
exist. Until then you will correctly see:

```
permission denied on secret/list: no policy grants 'list' on resource 'secret/list'
```

```bash
curl -sX PUT localhost:8083/v1/policies/admin \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"admin","rules":[{"paths":["secret/**"],
       "capabilities":["read","write","list","delete"]}]}'
```

Policies are scoped to the caller's tenant, so an `admin` policy in one tenant
grants nothing in another — even with the same name.

## Creating a superuser

```bash
curl -sX POST localhost:8082/v1/api-keys \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"platform-ops","tenant_id":"<any tenant>","is_superuser":true}'
```

MFA is forced on regardless of what you send. Then enrol and sign in as above,
and name the tenant you are acting on per request:

```bash
curl -H "Authorization: Bearer $SUPER_TOKEN" \
     -H "X-Vault-Act-Tenant: <other-tenant-id>" \
     localhost:8081/v1/secret/data/prod/db
```

`X-Vault-Act-Tenant` is ignored for everyone else, so it is not a tenant switch
— it is how someone already authorised across all tenants says which one they
mean. Every crossing is logged at WARN.

## Losing a phone

Use a recovery code in place of the 6-digit code. Each works once. If they are
all gone, a platform operator removes the enrolment so the user can re-enrol:

```sql
DELETE FROM shared.mfa_totp WHERE api_key_id = '<key id>';
```

## Rotating a key

```bash
curl -sX POST localhost:8082/v1/api-keys/<id>/rotate \
  -H "X-Admin-Token: $VAULT_ADMIN_TOKEN" -H "X-Tenant-Id: <tenant>"
```

Rotation carries `is_superuser` and `mfa_required` forward — it replaces a key,
it does not re-grade it.
