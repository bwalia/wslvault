# Two-region HA for wslvault

How the active/active region mesh is built, deployed and operated. Everything
here is GitOps-managed: the cluster state is a function of `deploy/gitops/` on
`main`, and Argo CD self-heals drift.

---

## 1. What a "region" is

One region is one complete, self-contained wslvault release:

| | region-a | region-b |
|---|---|---|
| Namespace | `wslvault` | `wslvault-b` |
| Node | `cloud001` (Manchester) | `cloud003` (London) |
| API host | `vault.workstation.co.uk` | `vault-b.workstation.co.uk` |
| Peer host | `vault-a.workstation.co.uk` | `vault-b.workstation.co.uk` |
| UI host | `vault-ui.workstation.co.uk` | `vault-ui-b.workstation.co.uk` |
| PostgreSQL | own StatefulSet, `local-path` | own StatefulSet, `local-path` |
| Values | `deploy/gitops/regions/region-a.values.yaml` | `…/region-b.values.yaml` |

Regions share **nothing** at runtime except key material. They do not share a
database, a node, or a pod network.

### Why fully independent, rather than one stretched cluster

The edge nodes carry `network.k3s1/cross-node=unavailable`: flannel VXLAN
between an edge PoP and the LAN nodes is unroutable. A pod on `cloud001` cannot
reach a pod on any other node. So a region cannot be spread across nodes, and
two regions cannot share a database. Each is pinned whole to one node, and they
talk to each other over the public internet like any two datacentres would.

---

## 2. How replication works

```
   region-a (cloud001)                          region-b (vps002)
   ┌────────────────────┐                    ┌────────────────────┐
   │ secret-engine      │                    │ secret-engine      │
   │   writes secret    │                    │   writes secret    │
   │        ↓           │                    │        ↓           │
   │ system.            │                    │ system.            │
   │  replication_events│                    │  replication_events│
   │        ↓           │                    │        ↓           │
   │ replication-agent  │                    │ replication-agent  │
   │  :8091             │                    │  :8091             │
   └────────┬───────────┘                    └───────────┬────────┘
            │                                            │
            │  GET /v1/replication/events                │
            │  Authorization: Bearer <mesh peer token>   │
            │                                            │
            └──────────────► public edge ◄───────────────┘
                    vault-a…            vault-b…
```

Each region's `replication-agent` polls **every peer** every
`replicationAgent.pollIntervalMs` (500ms), pulls events it has not seen, and
applies them locally. Conflicts resolve by `last_write_wins` (configurable to
`vector_clock` or `manual`). Leader election via PostgreSQL advisory locks
means only one replica per region consumes, so extra replicas are standby.

Loop prevention is in the database: the trigger functions in
`015_replication_event_triggers.sql` skip emitting an event when
`app.replication_agent = 'true'`, which the applier sets before writing.

### The peer API is authenticated

`GET /v1/replication/events` serves the outbox. That stream contains ciphertext
and DEK ids (`secret_upsert`), **cleartext RBAC policy documents**
(`policy_update`), and the tenant roster including `root_key_id`
(`tenant_update`). Regions peer over the public internet, so the endpoint is
reachable from anywhere.

It therefore requires `Authorization: Bearer <token>` against the shared mesh
token, compared in constant time
(`services/replication-agent/src/auth.rs`). It **fails closed**: with no token
configured the route returns `503` rather than serving the outbox openly.
`/health`, `/ready` and `/metrics` stay unauthenticated for probes and
Prometheus.

### The route is published only once the image enforces the token

`replicationAgent.publishPeerEndpoint` defaults to **false**, so
`/v1/replication` is absent from the edge Ingress and peers cannot pull.
Regions do not replicate in that state — which is the safe failure.

Both regions now run
`bwalia/wslvault-replication-agent:4168bb718f35c99987994c6402f22328e960ce62`,
the first image built from main containing `auth.rs`, and the flag is on.
Pinning the sha matters: `global.imageTag` (0.1.0) was re-pushed with the same
code, but `imagePullPolicy: IfNotPresent` means nodes keep the cached pre-auth
layer — only a new tag actually pulls it.

The guard lives in the service binary, so an image built before it ignores
`REPLICATION_PEER_TOKEN` completely and serves the outbox to anyone who reaches
the ingress. The env var being wired by the chart proves nothing. This was
observed for real: with `0.1.0` deployed, an unauthenticated request to
`/v1/replication/events` returned `200`, and so did one carrying a nonsense
bearer token.

Before enabling, confirm the running image actually rejects:

```bash
curl -o /dev/null -w '%{http_code}\n' \
  "https://<region-host>/v1/replication/events?source_region=x"
# 401 or 503 -> guarded; safe to set publishPeerEndpoint: true
# 200        -> pre-auth image; leave it false
```

Then set it in **every** region's values file and let Argo sync.

---

## 3. Key material — the one thing regions must share

Four values must be **byte-identical in every region**:

| Key | Why identical |
|---|---|
| `root-key` | region B decrypts region A's replicated ciphertext with its *own* root key |
| `jwt-secret` | a token minted by A's identity-service is verified by B's secret-engine |
| `pki-root-key` | tenant CA private keys are envelope-encrypted with it |
| `replication-peer-token` | each region authenticates to its peers with it |

Get this wrong and nothing looks broken: pods are healthy, replication events
flow, and every applied secret is undecryptable garbage.

They live in one Secret per namespace, `wslvault-mesh-keys`, referenced from
values as `secrets.existingSecret`. **They are never in Git.**

```bash
# First region already holds encrypted data — adopt its existing keys, never
# generate new ones, or everything it has stored becomes unreadable.
./scripts/wslvault-mesh-keys.sh adopt wslvault

# Confirm every region matches (prints fingerprints, not key material)
./scripts/wslvault-mesh-keys.sh verify

# A brand-new mesh with no data yet
./scripts/wslvault-mesh-keys.sh create

# A new region joining a live mesh
NAMESPACES="wslvault wslvault-b wslvault-c" \
  ./scripts/wslvault-mesh-keys.sh copy-from wslvault
```

---

## 4. Schema migrations

Previously nothing in the chart created the schema. The SQL under
`storage/postgres/init/` was only ever mounted into the docker-compose
Postgres; the Helm path never applied it, and region A was schema'd by hand.
That is exactly what made a second region unrepeatable.

`templates/migrations.yaml` now ships a Job that applies
`deploy/helm/wslvault/files/migrations/*.sql` through a ledger
(`system.schema_migrations`):

- each numbered file runs **at most once**, in its own transaction
- the file's sha256 is recorded; editing an applied file **fails the Job**
  rather than letting regions diverge
- a database that already has the schema but no ledger is **baselined**: files
  are recorded as applied without being executed (this is how region A adopts
  the Job safely)
- the region registry (`system.regions`) is re-seeded on every run, so peer
  endpoints can be corrected without a new migration

The Job is a plain resource, not a Helm hook, and its name carries a content
hash. A `pre-install` hook would deadlock on a fresh install (no Postgres yet)
and a `post-install` hook maps to Argo `PostSync`, which never fires while
services crash-loop on the missing schema.

> The chart carries its own copy of the SQL because Helm's `.Files` cannot read
> outside the chart directory and Argo renders the chart straight from Git.
> `scripts/validate-gitops.sh` fails if that copy drifts from
> `storage/postgres/init/`.

---

## 5. Standing up region B

### 5.0 Node choice: cloud003, not vps002

Region B runs on **cloud003**. vps002 was the original target but cannot run
this stack. Verified from inside the cluster:

```
$ kubectl -n kube-system get pods -o wide | grep vps002
coredns-node-h5rth      0/1   Running   31h   10.42.17.4      vps002
longhorn-manager-k5k7m  1/2   Running   31h   10.42.17.3      vps002
obs-promtail-edge-gchfk 0/1   Running   31h   10.42.17.6      vps002

# from a pod on vps002:
#   curl https://vault.workstation.co.uk  -> Could not resolve host
#   curl https://kubernetes.default.svc   -> Could not resolve host
#   curl -k https://10.43.0.1             -> timed out after 5s
#   curl -H 'Host: …' http://72.62.211.28 -> 200   (public egress works)
```

Diagnosis: `kube-dns` is `internalTrafficPolicy: Local`, so every node resolves
DNS through its **own** `coredns-node` pod. On vps002 that pod has never gone
Ready — its readiness probe returns 503 because CoreDNS cannot reach the API
server: the `kubernetes` Service endpoints are `192.168.1.104/118/77:6443`, LAN
addresses vps002 has no route to. `cloud001` and `cloud003` do have that route,
which is why their CoreDNS pods are Ready and wslvault runs there today.

Only host-network pods work on vps002. Every service in this chart addresses
PostgreSQL and its siblings by in-cluster DNS, so the stack cannot come up
there yet.

**Fix on the host** (needs SSH to vps002, not available from the repo): give
vps002 the same route to `192.168.1.0/24` that cloud001 and cloud003 have —
the WireGuard/VPN tunnel to the LAN control plane — then confirm:

```bash
kubectl -n kube-system delete pod -l k8s-app=kube-dns --field-selector spec.nodeName=vps002
kubectl -n kube-system get pods -o wide | grep vps002   # coredns-node must be 1/1
```

`kubectl logs`/`exec` against vps002 also fail (`502` dialing `85.190.106.88:10250`),
so the kubelet tunnel needs the same attention.

cloud003 is used instead: same isolation profile as cloud001 (edge taint,
`cross-node=unavailable`, traefik-edge, `local-path`), CoreDNS Ready, and a
genuinely separate site (`net-region=london` against cloud001's `manchester`).

**To move region B to vps002 once its route is restored**, change the two
`nodeSelector` hostnames in `deploy/gitops/regions/region-b.values.yaml` and
the host CIDR, then let Argo sync:

```yaml
global:
  scheduling:
    nodeSelector:
      kubernetes.io/hostname: vps002       # was cloud003
  edgeHostCidrs: &regionBEdgeCidrs
    - 10.42.17.0/31                        # vps002 podCIDR 10.42.17.0/24
postgresql:
  primary:
    nodeSelector:
      kubernetes.io/hostname: vps002
```

Note this is a **rebuild, not a migration**: PostgreSQL uses `local-path`, so
the data stays on the old node. Let region A replicate the content back into
the rebuilt region B, or dump and restore before switching.

### 5.1 DNS

Point the per-region hostnames at each region's node, and keep the shared alias
on whichever region should take default traffic.

Each region's Ingress serves its own per-region host; **exactly one region may
claim the shared alias**. `traefik-edge` is a single DaemonSet watching
Ingresses cluster-wide, so a host claimed by two Ingresses is ambiguous —
with the alias on both regions, `traefik-edge` on cloud003 resolved
`vault.workstation.co.uk` to region A's Services and hung, having no
pod-network route to cloud001. Failover is therefore two coordinated changes:
move the alias between regions' `edgeIngress.extraHosts`, and repoint the PoP
origin.

| Record | Target |
|---|---|
| `vault.workstation.co.uk` | PoP → region A origin (the shared alias) |
| `vault-a.workstation.co.uk` | `72.62.211.28` (cloud001) |
| `vault-b.workstation.co.uk` | `77.68.126.63` (cloud003) |
| `vault-ui-b.workstation.co.uk` | `77.68.126.63` (cloud003) |

The `-a`/`-b` hosts must resolve **before** the regions can peer: the
replication URLs in the roster use them.

### 5.2 Key material

```bash
export KUBECONFIG=~/.kube/k3s1.yaml

# Shared crypto keys: adopt region A's existing material into every region.
./scripts/wslvault-mesh-keys.sh adopt wslvault
./scripts/wslvault-mesh-keys.sh verify

# Database credentials are per-region, not shared. Region A adopts the password
# its PostgreSQL already uses; region B has no database yet, so it generates one.
./scripts/wslvault-mesh-keys.sh db-secret wslvault
./scripts/wslvault-mesh-keys.sh db-secret wslvault-b --generate
```

### 5.3 Bootstrap Argo CD

Once, by hand. Everything after this arrives through pull requests.

```bash
kubectl apply -f deploy/gitops/bootstrap/root-app.yaml
```

`wslvault-root` watches `deploy/gitops/` and applies `appproject.yaml` and
`applicationset.yaml`. The ApplicationSet then creates
`wslvault-region-a` and `wslvault-region-b`.

> Region A is **adopted**, not recreated. Its values file describes what is
> already running, so the first sync is a no-op apart from the new migrations
> Job (which baselines) and the peer wiring.

### 5.4 Verify

```bash
kubectl -n wslvault-b get pods
kubectl -n wslvault-b get jobs                    # migrations Job Complete
kubectl -n wslvault-b exec wslvault-postgresql-0 -- \
  psql -U wslvault -d wslvault -c 'SELECT id,status,is_local FROM system.regions'
```

Then check the mesh sees itself, from either region:

```bash
curl -s https://vault-b.workstation.co.uk/v1/sys/regions | jq
```

And that the peer API is published and guarded:

```bash
TOKEN=$(kubectl -n wslvault get secret wslvault-mesh-keys \
          -o jsonpath='{.data.replication-peer-token}' | base64 -d)

curl -s -o /dev/null -w '%{http_code}\n' \
  'https://vault-b.workstation.co.uk/v1/replication/events?source_region=region-a'
# 401 — expected

curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" \
  'https://vault-b.workstation.co.uk/v1/replication/events?source_region=region-a'
# 200
```

Both regions should then report each other active:

```
 region-a | active | local=true  | lag=0
 region-b | active | local=false | lag=14
```

---

## 6. Adding a third region

1. Add a list element to `deploy/gitops/applicationset.yaml`.
2. Add `deploy/gitops/regions/region-c.values.yaml` (copy region-b's).
3. Append region C to the `peers` roster in **every** region's values file —
   the roster is identical everywhere by design; each chart filters out its own
   entry.
4. `NAMESPACES="… wslvault-c" ./scripts/wslvault-mesh-keys.sh copy-from wslvault`
5. Point DNS at the new node.
6. Open a PR. CI checks the roster is consistent; Argo does the rest.

`scripts/validate-gitops.sh` fails the PR if step 3 is forgotten — a
half-updated roster gives one-directional replication, which is otherwise
invisible.

---

## 7. Operations

### Failover

Both regions are writable, so there is no failover step for writes — move the
shared alias `vault.workstation.co.uk` at the PoP to the surviving region.

To mark a region promoted in the registry:

```bash
curl -X POST https://vault-b.workstation.co.uk/v1/sys/regions/region-b/promote
```

### Watching replication health

```bash
# region-health's view of the mesh, from either region
curl -s https://vault-b.workstation.co.uk/v1/sys/regions | jq

# Prometheus: the replication-agent and region-health pods are scraped on
# their HTTP ports (8091 / 8092) via the chart's monitoring annotations.
```

`region-health` marks a peer `degraded` after one failed probe and `offline`
after three consecutive ones, polling every 10s.

### Common failure modes

| Symptom | Cause |
|---|---|
| Peer polls return `401` | mesh Secret differs between regions — run `wslvault-mesh-keys.sh verify` |
| Peer polls return `503` | `replication-peer-token` missing from the Secret; the API is failing closed |
| Peer polls return `404` | `replicationAgent.publishPeerEndpoint` is still false (the default) |
| Peers stuck `offline` while replication works | `<endpoint>/health` is not routed. `region-health` polls that exact path (hardcoded in `poller.rs`); the chart's `/healthz` goes to secret-engine and does not answer it. The `/health` route is rendered with `publishPeerEndpoint`. |
| Peer polls return `200` with **no** token | the deployed image predates the auth guard — set `publishPeerEndpoint: false` until a newer image ships |
| Replication silent, no errors | peer roster only updated in one region — `validate-gitops.sh` catches this |
| Secrets replicate but read back as garbage | `root-key` differs between regions |
| Replicated secret reads `decryption failed: key not found` | Expected today — the row replicates but its DEK does not. See "Known limits" below. |
| `key_not_found` for an API key that works elsewhere | API keys are per-region; they do not replicate. Mint one per region. |
| Services crash-loop on a new region | migrations Job did not complete — `kubectl -n <ns> logs job/wslvault-migrations-<hash>` |
| Migrations Job fails on checksum | an applied `.sql` was edited in place; add a new numbered file instead |
| Pods `Pending` on a new region | node taint/selector mismatch, or the node has no CoreDNS (see §5.0) |

### Rotating the peer token

Safe — it carries no data. Rotate in every namespace at once; peers 401 for the
few seconds between the two writes and retry.

## Known limits

Verified end to end on 2026-08-30 by writing `kv/data/ha-test/<stamp>` to
region A and reading it from region B:

- **The secret row replicates.** It arrives in region B's `shared.secrets`,
  and 61,906 replication events had been applied at the time of the test.
- **Its encryption key does not.** Region B's `system.key_descriptors` is
  empty, so the read fails with
  `decryption failed: key not found: <dek-id>`.

So replication currently moves ciphertext without the means to decrypt it.
Region B is a working vault for its own writes, and a faithful ciphertext
replica of region A, but it cannot serve reads of region A's secrets. Closing
this needs DEK replication (or a shared KEK-wrapped key store) — it is not a
configuration mistake.

**API keys are also per-region**, held per identity-service process rather than
in the replicated store on the images currently deployed. Session tokens *do*
work across regions, since every region verifies with the shared mesh JWT
secret.

For authentication mechanics see [`tenant-authentication.md`](tenant-authentication.md);
for obtaining a key see
[`operations/obtaining-credentials.md`](operations/obtaining-credentials.md).

### Rotating the root key

**Not** safe. Every secret in the mesh is encrypted under it. There is no
re-encryption path in the chart today; treat the root key as permanent.
