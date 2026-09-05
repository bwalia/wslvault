# Ring Promoter — WSLVault on k3s1

WSLVault is promoted through [Ring Promoter](https://rp.workstation.co.uk/)
(`workstation-ring-promoter` on k3s1), same pattern as JobShout.

There is **no Argo CD Application** for wslvault today. Deploys are Helm
releases in `wslvault` (region-a) and `wslvault-b` (region-b). Ring Promoter
owns the rollout: CI seeds a version tag into `int`, the k8sjob helm-upgrades
region-a, then auto-promotes to `test` for region-b.

The marketing site at **https://www.wslvault.org/** is a separate RP app
(`wslvault-www`) that uses the **github** deployer to dispatch
`.github/workflows/pages.yml`.

| File | What it is |
|------|------------|
| [`wslvault.yaml`](wslvault.yaml) | HA vault app (`deployer: k8sjob`) |
| [`wslvault-www.yaml`](wslvault-www.yaml) | Marketing site app (`deployer: github`) |
| [`rbac.yaml`](rbac.yaml) | RoleBindings for `ring-deploy-job` in both HA namespaces |

## One-time bootstrap on k3s1

```sh
export KUBECONFIG=~/.kube/k3s1.yaml
kubectl apply -f deploy/ring-promoter/rbac.yaml
```

Append the `apps:` item from `wslvault.yaml` to ConfigMap
`workstation-ring-promoter/ring-promoter-config` (`data.config.yaml`), apply,
and roll the pod. **Do not** append `wslvault-www` until `RP_GITHUB_TOKEN` is
on the Secret — RP validates github-deployer apps at startup and CrashLoops
if that env is empty.

```sh
kubectl apply -f <path-to-updated-configmap>
kubectl rollout restart deploy/ring-promoter -n workstation-ring-promoter
```

### GitHub token for www (required before registering `wslvault-www`)

`wslvault-www` uses the github deployer. The control-plane Secret must carry
a token that can `workflow_dispatch` on this repo **before** the app is in
the ConfigMap:

```sh
# Fine-grained PAT or GitHub App token: actions:write, contents:read on bwalia/wslvault
kubectl -n workstation-ring-promoter create secret generic ring-promoter \
  --from-literal=RP_API_TOKEN="$(kubectl -n workstation-ring-promoter get secret ring-promoter -o jsonpath='{.data.RP_API_TOKEN}' | base64 -d)" \
  --from-literal=RP_DB_DSN="$(kubectl -n workstation-ring-promoter get secret ring-promoter -o jsonpath='{.data.RP_DB_DSN}' | base64 -d)" \
  --from-literal=RP_GITHUB_TOKEN="<token>" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deploy/ring-promoter -n workstation-ring-promoter
```

## Vault HA (`wslvault`)

1. Ring Promoter creates Job `rp-wslvault-<ring>-…` in `ring-exec`.
2. The Job clones `bwalia/wslvault` at `RP_VERSION` (a `vX.Y.Z` tag).
3. It `helm upgrade --install`s `deploy/helm/wslvault` with the matching
   region values file and `--set` image tags to `RP_VERSION`.
4. Health is `GET /api/version` on that region's vault-ui, requiring the
   JSON `version` field to equal the seeded tag.

| Ring | `target_env` | Namespace | Pipeline label | Health | Auto-promote |
|------|--------------|-----------|----------------|--------|--------------|
| `int` | `region-a` | `wslvault` | `region-a · Manchester` | `https://vault-ui.workstation.co.uk/api/version` | yes |
| `test` | `region-b` | `wslvault-b` | `region-b · London` | `https://vault-ha.workstation.co.uk/api/version` | no |

## Marketing site (`wslvault-www`)

**Every push to `main`** also runs `.github/workflows/pages.yml` directly, so
https://www.wslvault.org/ stays current without waiting on Ring Promoter. The
footer shows the published version tag (exact git tag, else `git describe`,
else short SHA).

Ring Promoter path (optional / tracked in the RP UI):

1. Seed/promote dispatches `.github/workflows/pages.yml` with
   `DEPLOY_BRANCH=<version>` and `ENV=www`.
2. The workflow builds `www/`, writes `public/version.json` with that version,
   and publishes to GitHub Pages.
3. Health is `GET https://www.wslvault.org/version.json` with
   `health_version_field: version`.

| Ring | `target_env` | Pipeline label | Health | Auto-promote |
|------|--------------|----------------|--------|--------------|
| `int` | `www` | `www.wslvault.org · int` | `/version.json` | yes |
| `test` | `www` | `www.wslvault.org` | `/version.json` | no |

There is a single live hostname; both rings deploy it. `int` auto-promotes to
`test` (the next consecutive ring — RP cannot skip to `prod`).

## CI

### Vault release tags

On every new release tag cut by `.github/workflows/ci.yml` (`auto-tag`), the
`seed-ring-promoter` job POSTs:

```http
POST https://rp.workstation.co.uk/api/apps/wslvault/seed?async=1
{"ring":"int","version":"v1.0.N"}
```

### www/ changes

`.github/workflows/seed-www-ring-promoter.yml` seeds `wslvault-www` int with
the commit SHA (or a dispatch input):

```http
POST https://rp.workstation.co.uk/api/apps/wslvault-www/seed?async=1
{"ring":"int","version":"<sha>"}
```

Repo secrets required:

| Secret | Purpose |
|--------|---------|
| `RP_API_TOKEN` | Bearer token for `rp.workstation.co.uk` |
| `RP_URL` | Optional override; defaults to `https://rp.workstation.co.uk` |

Cluster secret (www only): `RP_GITHUB_TOKEN` on `workstation-ring-promoter/ring-promoter`.

Manual seeds:

```sh
TOKEN=$(kubectl -n workstation-ring-promoter get secret ring-promoter \
  -o jsonpath='{.data.RP_API_TOKEN}' | base64 -d)
curl --fail -sS -X POST 'https://rp.workstation.co.uk/api/apps/wslvault/seed?async=1' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ring":"int","version":"v1.0.14"}'
curl --fail -sS -X POST 'https://rp.workstation.co.uk/api/apps/wslvault-www/seed?async=1' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ring":"int","version":"main"}'
```

Track: <https://rp.workstation.co.uk/?app=wslvault> ·
<https://rp.workstation.co.uk/?app=wslvault-www>

## Companion change on `bwalia/ring-promoter`

Pipeline cards show `rings.*.display_name` only after Ring Promoter gains that
field (API + UI). This agent cannot push to that repo; apply the bundled patch
from a machine with write access:

```bash
cd ~/Documents/Work/ring-promoter
git checkout -b cursor/ring-display-name-region-labels origin/main
git am /path/to/wslvault/deploy/ring-promoter/upstream-display-name.patch
# then rebuild the embedded UI:
cd web && npm ci && npm run build:embed && cd ..
git add internal/web/static && git commit --amend --no-edit   # or a follow-up commit
git push -u origin HEAD && gh pr create
```

Or pull the full commit (including embedded UI) from the bundle:

```bash
git fetch /path/to/wslvault/deploy/ring-promoter/upstream-display-name.bundle \
  cursor/ring-display-name-region-labels:cursor/ring-display-name-region-labels
git checkout cursor/ring-display-name-region-labels
git push -u origin HEAD && gh pr create
```
