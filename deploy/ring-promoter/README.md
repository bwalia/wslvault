# Ring Promoter — WSLVault on k3s1

WSLVault is promoted through [Ring Promoter](https://rp.workstation.co.uk/)
(`workstation-ring-promoter` on k3s1), same pattern as JobShout.

There is **no Argo CD Application** for wslvault today. Deploys are Helm
releases in `wslvault` (region-a) and `wslvault-b` (region-b). Ring Promoter
owns the rollout: CI seeds a version tag into `int`, the k8sjob helm-upgrades
region-a, then auto-promotes to `test` for region-b.

| File | What it is |
|------|------------|
| [`wslvault.yaml`](wslvault.yaml) | App registry entry (`deployer: k8sjob`) |
| [`rbac.yaml`](rbac.yaml) | RoleBindings for `ring-deploy-job` in both region namespaces |

## One-time bootstrap on k3s1

```sh
export KUBECONFIG=~/.kube/k3s1.yaml
kubectl apply -f deploy/ring-promoter/rbac.yaml
```

Append the `apps:` item from `wslvault.yaml` to the workstation Ring Promoter
ConfigMap (`bwalia/ring-promoter` → `deploy/k8s/configmap.yaml`), apply it,
and roll the pod:

```sh
kubectl apply -f <path-to-updated-configmap>
kubectl rollout restart deploy/ring-promoter -n workstation-ring-promoter
```

## What a seed/promote does

1. Ring Promoter creates Job `rp-wslvault-<ring>-…` in `ring-exec`.
2. The Job clones `bwalia/wslvault` at `RP_VERSION` (a `vX.Y.Z` tag).
3. It `helm upgrade --install`s `deploy/helm/wslvault` with the matching
   region values file and an image-override layer that sets every service
   (and `global.imageTag`) to `RP_VERSION`.
4. Health is `GET /api/version` on that region's vault-ui, requiring the
   JSON `version` field to equal the seeded tag.

| Ring | `target_env` | Namespace | Pipeline label | Health | Auto-promote |
|------|--------------|-----------|----------------|--------|--------------|
| `int` | `region-a` | `wslvault` | `region-a · Manchester` | `https://vault-ui.workstation.co.uk/api/version` | yes |
| `test` | `region-b` | `wslvault-b` | `region-b · London` | `https://vault-ha.workstation.co.uk/api/version` | no |

Ring cards in the RP UI show the **pipeline label** (`display_name`) as the
primary title, with the shared ring name (Integration / Test) as a subtitle.
That needs Ring Promoter support for `rings.*.display_name` (see the companion
PR on `bwalia/ring-promoter`).

## CI

On every new release tag cut by `.github/workflows/ci.yml` (`auto-tag`), the
`seed-ring-promoter` job POSTs:

```http
POST https://rp.workstation.co.uk/api/apps/wslvault/seed?async=1
{"ring":"int","version":"v1.0.N"}
```

Repo secrets required:

| Secret | Purpose |
|--------|---------|
| `RP_API_TOKEN` | Bearer token for `rp.workstation.co.uk` (from `kubectl -n workstation-ring-promoter get secret ring-promoter -o jsonpath='{.data.RP_API_TOKEN}' \| base64 -d`) |
| `RP_URL` | Optional override; defaults to `https://rp.workstation.co.uk` |

Manual seed:

```sh
TOKEN=$(kubectl -n workstation-ring-promoter get secret ring-promoter \
  -o jsonpath='{.data.RP_API_TOKEN}' | base64 -d)
curl --fail -sS -X POST 'https://rp.workstation.co.uk/api/apps/wslvault/seed?async=1' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ring":"int","version":"v1.0.14"}'
```

Track the app at <https://rp.workstation.co.uk/?app=wslvault>.
