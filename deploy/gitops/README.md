# GitOps: the wslvault region mesh

Argo CD owns both regions from this directory. Cluster state is a function of
`main`; `selfHeal: true` reverts anything changed by hand.

```
deploy/gitops/
├── bootstrap/root-app.yaml   applied ONCE by hand; watches this directory
├── appproject.yaml           AppProject scoping regions to wslvault* namespaces
├── applicationset.yaml       ← the region roster lives here
└── regions/
    ├── region-a.values.yaml  cloud001 / wslvault      (the original deployment)
    └── region-b.values.yaml  vps002   / wslvault-b
```

## Bootstrap

```bash
export KUBECONFIG=~/.kube/k3s1.yaml
./scripts/wslvault-mesh-keys.sh adopt wslvault   # see docs/ha-two-region.md §3
kubectl apply -f deploy/gitops/bootstrap/root-app.yaml
```

That is the only imperative step. Everything afterwards is a pull request.

## Changing a region

Edit its values file and open a PR. `.github/workflows/gitops-validate.yml`
renders every region, schema-validates the output, and checks the invariants
that are silent when broken:

- every region in the ApplicationSet has a values file and vice versa
- regions do not share a namespace
- all regions carry an **identical** peer roster (a half-updated roster gives
  one-directional replication with no error anywhere)
- all regions read key material from the **same** Secret (different keys means
  replicated ciphertext never decrypts)
- the chart's vendored SQL still matches `storage/postgres/init/`
- no region renders placeholder key material

Run the same checks locally:

```bash
./scripts/validate-gitops.sh
```

## Adding a region

See `docs/ha-two-region.md` §6. Short version: one list element here, one
values file, and append the region to the roster in *every* region's file.

## What is deliberately not in Git

The mesh key material (`wslvault-mesh-keys`: root key, JWT secret, PKI root
key, replication peer token). Values files reference it by name only; it is
installed with `scripts/wslvault-mesh-keys.sh`. The `ignoreDifferences` block
in the ApplicationSet stops Argo from trying to reconcile Secret contents.
