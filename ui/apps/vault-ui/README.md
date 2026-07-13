# vault-ui

Web console for **WSLVault** — a Next.js (App Router) dashboard for tenants,
secrets, transit, policies, identity, SCIM, cluster, regions, leases, and audit.

## How it talks to the backend

The browser calls same-origin paths under `/api/<service>/*`. Next.js
[rewrites](./next.config.ts) proxy each prefix to a backend base URL, stripping
the `/api/<service>` segment:

| Prefix | Env var | Dev default |
|--------|---------|-------------|
| `/api/identity/*` | `IDENTITY_URL` | `http://localhost:18082` |
| `/api/secret/*`   | `SECRET_URL`   | `http://localhost:8081`  |
| `/api/transit/*`  | `TRANSIT_URL`  | `http://localhost:18086` |
| `/api/policy/*`   | `POLICY_URL`   | `http://localhost:8083`  |
| `/api/audit/*`    | `AUDIT_URL`    | `http://localhost:18085` |
| `/api/lease/*`    | `LEASE_URL`    | `http://localhost:18084` |
| `/api/gateway/*`  | `GATEWAY_URL`  | `http://localhost:8088`  |

So `/api/identity/v1/tenants` → `${IDENTITY_URL}/v1/tenants`.

## Run locally

```bash
npm install
npm run dev        # http://localhost:3011
```

### Point at a live cluster via the edge ingress

Because the `vault.workstation.co.uk` ingress already routes every `/v1/*` path
to the right service, you can send all prefixes to the one public host:

```bash
IDENTITY_URL=https://vault.workstation.co.uk \
SECRET_URL=https://vault.workstation.co.uk \
TRANSIT_URL=https://vault.workstation.co.uk \
POLICY_URL=https://vault.workstation.co.uk \
AUDIT_URL=https://vault.workstation.co.uk \
LEASE_URL=https://vault.workstation.co.uk \
GATEWAY_URL=https://vault.workstation.co.uk \
npm run dev
```

If the edge serves a self-signed cert, prefix with
`NODE_TLS_REJECT_UNAUTHORIZED=0` (development only).

## Log in

Authenticate with a WSLVault API key (`wslv_…`); the UI exchanges it at
`POST /v1/auth/api-key` for a JWT and sends `Authorization: Bearer <jwt>` plus
`X-Tenant-Id` on every request.

## Known limitations

- **Audit** and **Leases** backends are gRPC-only over their HTTP port (only
  `/health` is served), so those pages return errors against a real cluster.
- **Regions / Cluster / SCIM** pages call `/api/gateway/*` with pre-gateway
  paths (`/v1/regions`, `/v1/scim/Users`) that don't match the current backend
  routes (`/v1/sys/regions`, `/scim/v2/Users`); region-health is also not in the
  edge ingress. These need path alignment before they work end-to-end.

## Build

```bash
npm run build      # produces .next/standalone (output: 'standalone')
npm start
```
