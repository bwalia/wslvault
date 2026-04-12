# WSLVault Web UI — Build Prompt

## Project Overview

Build a sophisticated, production-quality web UI for **WSLVault** — a multi-tenant secrets management platform (similar to HashiCorp Vault). The UI lives at `ui/apps/vault-ui/` and talks to a REST/gRPC-HTTP backend running locally on several ports.

---

## Tech Stack

- **Framework**: React 18 + TypeScript
- **Routing**: React Router v6
- **State management**: Zustand
- **Styling**: Tailwind CSS + shadcn/ui component library
- **Data fetching**: TanStack Query (React Query v5)
- **Forms**: React Hook Form + Zod validation
- **Build tool**: Vite
- **Testing**: Vitest + Testing Library

---

## Backend API Summary

All requests go through the gateway at `http://localhost:8088` (or direct to services in dev).

### Auth
Every request (except `/v1/auth/*` and `/health`) requires:
- `Authorization: Bearer <jwt>` header
- `X-Tenant-Id: <tenant_id>` header

Auth flow: POST raw API key (`wslv_...`) to `POST /v1/auth/api-key` → receive JWT + `expires_at`.

### Service Endpoints (local dev direct-access ports)

| Service | Base URL | Swagger UI |
|---------|----------|------------|
| identity-service | `http://localhost:18082` | `/swagger-ui/` |
| secret-engine | `http://localhost:8081` | `/swagger-ui/` |
| transit-engine | `http://localhost:18086` | `/swagger-ui/` |
| policy-engine health | `http://localhost:8083` | — |
| lease-manager health | `http://localhost:18084` | — |
| audit-service health | `http://localhost:18085` | — |

---

## Application Structure

```
src/
  api/           # Typed API clients per service
  components/    # Shared UI components
  hooks/         # Custom hooks
  routes/        # Page components (one folder per section)
    auth/        # Login page
    tenants/     # Tenant management
    secrets/     # Secret browser & editor
    policies/    # Policy editor
    identity/    # API keys, service accounts
    leases/      # Active leases
    audit/       # Audit log viewer
    settings/    # App settings
  stores/        # Zustand stores (auth, tenant context)
```

---

## Core Features

### 1. Authentication & Session

**Login page** (`/login`):
- Input field for API key (`wslv_...` prefix)
- On submit: POST to `POST /v1/auth/api-key` → store JWT + `expires_at` in Zustand auth store (persisted to `sessionStorage`)
- Show JWT expiry countdown in the top nav
- Auto-logout when token expires; prompt re-login
- "Copy token" button for power users

**Auth store** (Zustand):
```ts
{ token: string | null, tenantId: string | null, policies: string[], expiresAt: Date | null }
```

---

### 2. Tenant Switcher (Global)

A persistent tenant context selector in the top navigation bar:
- Dropdown listing all tenants (fetched from `GET /v1/tenants`)
- Selected tenant ID stored in Zustand + sent as `X-Tenant-Id` on every request
- Badge showing tenant tier: `Shared` | `Dedicated` | `Sovereign`
- "New Tenant" shortcut button

**Tenant detail panel** (`/tenants/:id`):
- Fields: `slug`, `display_name`, `tier`, `root_key_id`, `created_at`
- Edit display name inline
- Soft-delete with confirmation dialog (requires typing the tenant slug)

**Tenant list page** (`/tenants`):
- Table with columns: Name, Slug, Tier, Created At, Status
- Create tenant form (modal): `slug` (validated: lowercase, alphanumeric, hyphens), `display_name`, `tier` selector
- Note: `root_key_id` is assigned automatically by the backend

---

### 3. Secret Browser (`/secrets`)

The primary feature. A two-panel layout:

**Left panel — Secret tree**:
- Hierarchical path browser (folder tree), fetched via `GET /v1/secret/list?prefix=`
- Click a folder node → drill into it (re-fetch with updated prefix)
- Click a secret leaf → open in right panel
- "New Secret" button at current path
- Breadcrumb navigation showing current path

**Right panel — Secret editor**:
- **Metadata bar**: path, current version, engine type, `cas_required` toggle, `max_versions` input
- **Data editor**: key-value table where each row is a secret field
  - "Add field" button, inline delete per row
  - Values hidden by default (eye toggle per row)
  - JSON toggle: switch between KV table and raw JSON editor
- **Version history**: tabs or dropdown for past versions (read-only)
  - Show `created_at`, `deleted_at`, `destroyed` flag per version
  - Restore button for soft-deleted versions
- **Actions**:
  - **Save** (PUT) — with optional CAS version field shown when `cas_required=true`
  - **Delete** (soft) — with confirmation, shows recovery note
  - **Destroy** (permanent) — dangerous action, requires typing the path to confirm, red destructive button
- **Metadata editor**: key-value pairs for `custom_metadata`

**Secret versioning notes**:
- Deleted ≠ Destroyed: deleted secrets can be recovered; destroyed ones cannot
- Always show version number prominently
- "Copy path" button

---

### 4. Policy Editor (`/policies`)

**Policy list**:
- Table: Name, Rule count, Last updated
- "New Policy" button
- Click row → open editor

**Policy editor** (full-page or modal):
- Policy name field (read-only after creation)
- Rule builder:
  - Each rule has: `paths[]` (tag input with glob hints) + `capabilities[]` (checkbox group)
  - Capabilities: `read`, `write`, `delete`, `list`, `create`, `update`, `deny`
  - `deny` checkbox shown in red; selecting it warns it overrides all other capabilities
  - Drag-to-reorder rules
  - "Add rule" / "Remove rule" buttons
- **YAML/JSON toggle**: show raw policy document alongside the visual builder
- **Test policy** panel: enter a `principal_id` + `action` + `resource` → call `Authorize` and show Allow/Deny + matched rule
- Save / Delete buttons

---

### 5. Identity & Access (`/identity`)

#### API Keys tab
- Table: Name, Key Prefix (`wslv_...`), Policies, Expires At, Last Used, Rate Limit
- **Create API key** (modal):
  - `name`, `tenant_id` (pre-filled from context), `policies[]` (multi-select from policy list), `path_prefixes[]` (tag input), `expires_in_seconds` (human duration picker), `rate_limit_per_minute`
- **Important UX**: raw key is only shown at creation in a modal with a prominent "Copy now — this is the only time" banner. After dismissal only `key_prefix` is available.
- Rotate button (generates new key, same warning)
- Revoke button (confirmation required)

#### Service Accounts tab
- Table: Name, Principal ID, Policies, Created At
- Create service account (modal): `name`, `policies[]`, `ttl_seconds`
- Token shown at creation with same "copy now" pattern

#### Leases tab (linked from `/leases`)
- Table: Lease ID, Target Type, State, Remaining TTL (live countdown), Renewable
- Renew button (for renewable leases) with increment input
- Revoke button with confirmation
- State badges: `Active` (green), `Renewing` (yellow), `Expired` (red), `Revoked` (grey)
- TTL shown as human duration (e.g., "23h 14m") with a progress bar depleting in real time

---

### 6. Audit Log (`/audit`)

**Filter bar**:
- Date range picker (start/end)
- Action filter (text input or dropdown of common actions: `secret.read`, `secret.write`, `auth.token.issue`, `policy.eval`, etc.)
- Principal filter (text input)
- Tenant filter (dropdown, defaults to current tenant)
- "Search" button

**Results table**:
- Columns: Timestamp, Action, Resource, Principal, Outcome, Client IP
- Outcome badge: `success` (green), `failure` (red), `error` (orange)
- Click row → expand detail drawer showing raw `details_json`
- Pagination: `limit` / `offset` with page controls and total count
- "Export CSV" button (client-side, from current page)

---

### 7. Transit Engine (`/transit`) — optional/advanced

- List transit keys (fetched via GET `/v1/transit/keys/:key_name`)
- Create key (`POST /v1/transit/keys/:key_name`)
- Rotate key (`POST /v1/transit/keys/:key_name/rotate`)
- Encrypt/Decrypt playground: input plaintext → call encrypt → show ciphertext, and vice versa
- Sign/Verify playground

---

### 8. Settings (`/settings`)

- **Backend URLs**: editable base URLs per service (stored in localStorage, used by API clients)
- **Theme toggle**: light / dark / system
- **Session info**: current token expiry, policies, tenant
- **About**: version info

---

## Navigation Structure

```
Top nav:
  [WSLVault logo]  [Tenant switcher ▼]          [Token expiry badge]  [User menu]

Left sidebar:
  🔑  Secrets
  📋  Policies
  👤  Identity
  📜  Audit Log
  🔐  Transit
  ⚙️  Settings
```

---

## API Client Pattern

Create a typed API client class per service. All clients share a base `request()` function that:
1. Reads token from auth store
2. Reads tenantId from tenant store
3. Injects `Authorization` and `X-Tenant-Id` headers automatically
4. On 401 → clears auth store, redirects to `/login`
5. On 429 → shows toast "Rate limited, slow down"
6. Wraps errors in a typed `ApiError` with `status`, `message`, `detail`

Example:
```ts
// src/api/secrets.ts
export const secretsApi = {
  list: (prefix: string) => request<{ paths: string[] }>(`GET /v1/secret/list?prefix=${prefix}`),
  get: (path: string, version?: number) => request<SecretResponse>(`GET /v1/secret/data/${path}`),
  put: (path: string, body: PutSecretBody) => request<PutSecretResponse>(`POST /v1/secret/data/${path}`, body),
  delete: (path: string, versions: number[]) => request<void>(`POST /v1/secret/delete/${path}`, { versions }),
  destroy: (path: string, versions: number[]) => request<void>(`POST /v1/secret/destroy/${path}`, { versions }),
  metadata: (path: string) => request<SecretMetadata>(`GET /v1/secret/metadata/${path}`),
}
```

---

## Key UX Principles

1. **Tenant context is always visible** — the selected tenant is in the top nav at all times; every destructive action confirms the target tenant.
2. **Secrets are sensitive** — all secret values are hidden by default (•••••); require explicit toggle to reveal; never log or display in URLs.
3. **Destructive actions require confirmation** — delete requires one click + confirmation dialog; destroy requires typing the resource name.
4. **Token lifecycle awareness** — show expiry countdown; warn at 5 minutes remaining; auto-logout with helpful "session expired" message.
5. **Copy-once pattern** — API keys and initial tokens must be copyable at creation and clearly state they cannot be retrieved again.
6. **Optimistic UI** — use TanStack Query mutations with optimistic updates for fast feel; rollback on error with toast notification.
7. **Empty states** — every list view has a helpful empty state with a CTA ("No secrets yet — create your first secret").
8. **Loading skeletons** — use skeleton placeholders, not spinners, for content loading.
9. **Error boundaries** — wrap each route in an error boundary that shows a friendly error card with retry option.
10. **Responsive** — usable on 1280px+ desktop; sidebar collapses to icon-only below 1024px.

---

## Data Types (TypeScript)

```ts
// Core entity types to implement in src/types/

type TenantTier = 'Shared' | 'Dedicated' | 'Sovereign'
type Capability = 'read' | 'write' | 'delete' | 'list' | 'create' | 'update' | 'deny'
type LeaseState = 'Active' | 'Renewing' | 'Expired' | 'Revoked'
type AuditOutcome = 'success' | 'failure' | 'error'

interface Tenant { id: string; slug: string; display_name: string; tier: TenantTier; root_key_id: string; created_at: string; updated_at: string }
interface SecretMetadata { id: string; tenant_id: string; path: string; engine: string; current_version: number; max_versions: number; cas_required: boolean; created_at: string; updated_at: string; custom_metadata: Record<string,string> }
interface SecretVersion { version: number; created_at: string; deleted_at?: string; destroyed: boolean }
interface PolicyDocument { name: string; rules: PolicyRule[] }
interface PolicyRule { paths: string[]; capabilities: Capability[] }
interface ApiKeyMetadata { id: string; name: string; tenant_id: string; key_prefix: string; policies: string[]; path_prefixes: string[]; created_by: string; created_at: string; expires_at?: string; last_used_at?: string; rate_limit_per_minute?: number }
interface Lease { id: string; tenant_id: string; target_type: string; state: LeaseState; ttl_seconds: number; max_ttl_seconds: number; renewable: boolean; issued_at: string; expires_at: string; revoked_at?: string }
interface AuditEvent { event_id: string; tenant_id: string; principal_id: string; action: string; resource: string; outcome: AuditOutcome; timestamp: string; client_ip: string }
```

---

## Implementation Order (Suggested)

1. **Project setup** — Vite + React + TS + Tailwind + shadcn/ui + TanStack Query + Zustand + React Router
2. **Auth store + Login page** — API key exchange, JWT storage, expiry handling
3. **Layout shell** — top nav (tenant switcher, expiry badge), sidebar navigation, route outlets
4. **API client base** — typed `request()` with auth injection, error handling, 401 redirect
5. **Tenant management** — list, create, detail pages
6. **Secret browser** — tree navigation, secret viewer/editor, version history
7. **Policy editor** — list, visual rule builder, test panel
8. **Identity** — API keys tab, service accounts tab
9. **Leases** — live TTL countdown table, renew/revoke
10. **Audit log** — filter bar, paginated table, detail drawer
11. **Transit engine** — key management + encrypt/decrypt playground
12. **Settings** — backend URLs, theme, session info
13. **Polish** — empty states, skeletons, error boundaries, responsive layout

---

## Notes

- The backend services do **not** have a pre-built JS SDK in this repo — you must implement the API clients from scratch using the REST endpoints documented above.
- Secret values are **never stored in plaintext** by the backend; the UI only ever sends/receives raw bytes (JSON-encoded). There is no need to handle encryption client-side.
- The gateway at `:8088` handles routing in production. For local dev, talk directly to each service using the ports listed above.
- Use environment variables (via Vite's `import.meta.env`) for base URLs:
  ```
  VITE_IDENTITY_URL=http://localhost:18082
  VITE_SECRET_URL=http://localhost:8081
  VITE_TRANSIT_URL=http://localhost:18086
  VITE_POLICY_URL=http://localhost:8083
  VITE_AUDIT_URL=http://localhost:18085
  VITE_LEASE_URL=http://localhost:18084
  ```
