# deploy/gitops: region configuration for the wslvault mesh

This directory holds the **per-region Helm values** for the two production
regions, plus validation for them. The regions are deployed by
**Ring Promoter**, not by Argo CD. See
[`deploy/ring-promoter/README.md`](../ring-promoter/README.md) for the release
pipeline.

```
deploy/gitops/
├── regions/
│   ├── region-a.values.yaml  k3s1 / ns wslvault    (Ring Promoter ring int)
│   └── region-b.values.yaml  k3s1 / ns wslvault-b  (Ring Promoter ring test)
├── applicationset.yaml       Argo CD manifests: NOT applied, see below
├── appproject.yaml           〃
└── bootstrap/root-app.yaml   〃
```

## How a region is actually deployed

Both regions are plain Helm releases named `wslvault`. Ring Promoter rolls them
out:

1. A release tag `vX.Y.Z` is seeded into the `int` ring. The CI `auto-tag` job
   does this, or you can seed manually, as `deploy/ring-promoter/README.md`
   shows.
2. A Ring Promoter Job clones `bwalia/wslvault` **at that tag** and runs
   `helm upgrade --install` against `deploy/helm/wslvault` with
   `-f deploy/gitops/regions/<region>.values.yaml`. It overrides every image
   tag with the release version.
3. `int` deploys region-a and auto-promotes to `test`, which deploys region-b.

Consequences worth knowing:

- **A values change reaches production only with the next release tag.**
  Merging to `main` changes nothing on the cluster, because the Job clones the
  tag, not `main`.
- **Nothing reverts manual changes.** There is no Argo `selfHeal`. A
  `kubectl edit` or an out-of-band `helm upgrade` stays until the next Ring
  Promoter deploy overwrites it.
- **Image tags in the values files are overridden** by the release version at
  deploy time. Bumping them by hand does not pin anything.

Check what is running:

```bash
export KUBECONFIG=~/.kube/k3s1.yaml
helm -n wslvault   list
helm -n wslvault-b list
kubectl -n wslvault get deploy \
  -o 'custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image'
```

## Changing a region

Edit its values file, run the validation, and open a PR. The change ships with
the next release tag.

```bash
./scripts/validate-gitops.sh
```

This needs `helm` and `python3` **with PyYAML**. Without PyYAML, several checks
die with `ModuleNotFoundError` and the script reports "GitOps validation
failed" even though nothing is wrong. `kubeconform` is used when installed. A
throwaway venv works:

```bash
python3 -m venv /tmp/gitops-venv && /tmp/gitops-venv/bin/pip install -q pyyaml
PATH=/tmp/gitops-venv/bin:$PATH ./scripts/validate-gitops.sh
```

The script checks the invariants that fail silently when broken:

- every region in `applicationset.yaml` has a values file and vice versa
  (the ApplicationSet is still used as the region roster)
- regions do not share a namespace
- all regions carry an **identical** peer roster. A half-updated roster gives
  one-directional replication with no error anywhere.
- all regions read key material from the **same** Secret. Different keys mean
  replicated ciphertext never decrypts.
- the chart's vendored SQL still matches `storage/postgres/init/`
- no region renders placeholder key material
- every region renders and lints, and pins the same images

`.github/workflows/gitops-validate.yml` runs the same script on PRs, but GitHub
Actions is currently disabled on this repository. Run it locally until the
workflows are re-enabled.

## Adding a region

See `docs/ha-two-region.md` §6, but note that its Argo steps do not apply. You
need:

- a new values file,
- a matching element in `applicationset.yaml` (for the validation roster),
- the new peer appended to the roster in **every** region's values file,
- a new `case` branch and namespace in `deploy/ring-promoter/wslvault.yaml`,
- a ring for the region in Ring Promoter.

## About the Argo CD manifests

`bootstrap/root-app.yaml`, `appproject.yaml` and `applicationset.yaml`
describe a GitOps setup that was designed but **never applied**. k3s1 has no
`wslvault*` Application, ApplicationSet or AppProject.

**Do not apply `root-app.yaml` while Ring Promoter deploys these regions.**
Argo would track `main` with `selfHeal: true`, while Ring Promoter deploys
release tags. The two controllers would fight over the same objects: Argo
would revert every Ring Promoter rollout, and Ring Promoter would overwrite
Argo's sync. Moving to Argo means removing the Ring Promoter app (and its
`ring-deploy-job` RoleBindings) in the same change.

## What is deliberately not in Git

The mesh key material (`wslvault-mesh-keys`: root key, JWT secret, PKI root
key, replication peer token, audit signing key). Values files reference it by
name only; it is installed with `scripts/wslvault-mesh-keys.sh`. The
`ignoreDifferences` block in the ApplicationSet stops Argo from trying to
reconcile Secret contents.

### Two optional keys in the same Secret

Because every region's values file sets `secrets.existingSecret:
wslvault-mesh-keys`, the chart stops rendering its own per-purpose Secrets and
resolves *all* key lookups against that one Secret — including two that are
deployment config rather than mesh material:

| Key | Env var | Absent means |
|-----|---------|--------------|
| `smtp-password` | `SMTP_PASSWORD` | identity-service connects to the SMTP relay **unauthenticated**; Gmail rejects the send, so invitations are created but no email arrives |
| `admin-token` | `VAULT_ADMIN_TOKEN` | the bootstrap path is off — the only way to mint an API key is a JWT already carrying the platform-admin policy |

Both `secretKeyRef`s are `optional: true`, so a missing key starts the pod
normally and fails only at use. Neither is generated by the script; set them on
a first install, or add them later with a merge patch:

```bash
kubectl -n wslvault patch secret wslvault-mesh-keys --type merge \
  -p "{\"data\":{\"smtp-password\":\"$(printf %s 'APP_PASSWORD' | base64)\"}}"
kubectl -n wslvault rollout restart deploy/wslvault-identity-service
```

The restart is required: `secretKeyRef` env is read once at pod start.

For Gmail this must be an **app password** (2-Step Verification on), entered
without the spaces Google displays it with. An account password is rejected
with SMTP 535.

`apply_secret` in the script carries both keys forward from whatever the
namespace already holds, so re-running `adopt`/`create`/`copy-from` no longer
wipes them; `SMTP_PASSWORD` and `VAULT_ADMIN_TOKEN` in the environment seed a
first value. Note that `copy-from` does *not* propagate them to the joining
region — it preserves the target's own, so set them per namespace.
