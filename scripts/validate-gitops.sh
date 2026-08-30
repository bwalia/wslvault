#!/usr/bin/env bash
# Validate the wslvault region mesh: chart renders, manifests are schema-valid,
# and the region roster is internally consistent.
#
# Runs identically in CI and locally:
#   ./scripts/validate-gitops.sh
#
# Requires: helm, python3 (with PyYAML). kubeconform is used when present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/wslvault"
GITOPS="$ROOT/deploy/gitops"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

fail=0
note() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
note "migrations vendored into the chart match storage/postgres/init"
# The chart needs the SQL inside its own directory because Helm's .Files cannot
# reach outside the chart root, and Argo CD renders the chart straight from Git.
# That copy is the thing that can silently rot, so it is checked here rather
# than trusted.
if diff -rq "$ROOT/storage/postgres/init" "$CHART/files/migrations" >"$OUT/migdiff" 2>&1; then
  ok "$(ls "$CHART/files/migrations"/*.sql | wc -l | tr -d ' ') files in sync"
else
  bad "chart migrations have drifted from storage/postgres/init:"
  sed 's/^/       /' "$OUT/migdiff"
  echo "       fix with: cp storage/postgres/init/*.sql $CHART/files/migrations/"
fi

# ─────────────────────────────────────────────────────────────────────────────
note "every region in the ApplicationSet has a values file, and vice versa"
python3 - "$GITOPS" <<'PY' || fail=1
import sys, pathlib, yaml
gitops = pathlib.Path(sys.argv[1])
appset = yaml.safe_load((gitops / "applicationset.yaml").read_text())
declared = {e["region"] for e in appset["spec"]["generators"][0]["list"]["elements"]}
files = {p.name.removesuffix(".values.yaml") for p in (gitops / "regions").glob("*.values.yaml")}
rc = 0
for r in sorted(declared - files):
    print(f"  \033[31mFAIL\033[0m {r} is in the ApplicationSet but has no regions/{r}.values.yaml"); rc = 1
for r in sorted(files - declared):
    print(f"  \033[31mFAIL\033[0m regions/{r}.values.yaml exists but {r} is not in the ApplicationSet"); rc = 1
if not rc:
    print(f"  \033[32mok\033[0m   {len(declared)} regions: {', '.join(sorted(declared))}")

# Namespaces must be distinct: two regions sharing one namespace would collide
# on every resource name, since the release name is 'wslvault' in both.
ns = [e["namespace"] for e in appset["spec"]["generators"][0]["list"]["elements"]]
if len(ns) != len(set(ns)):
    print(f"  \033[31mFAIL\033[0m regions share a namespace: {ns}"); rc = 1
sys.exit(rc)
PY

# ─────────────────────────────────────────────────────────────────────────────
note "region roster is identical across regions and self-consistent"
python3 - "$GITOPS" <<'PY' || fail=1
import sys, pathlib, yaml
gitops = pathlib.Path(sys.argv[1])
regions = {}
for p in sorted((gitops / "regions").glob("*.values.yaml")):
    regions[p.name.removesuffix(".values.yaml")] = yaml.safe_load(p.read_text())

rc = 0
rosters = {}
for name, v in regions.items():
    region = v["global"]["region"]
    if region["id"] != name:
        print(f"  \033[31mFAIL\033[0m {name}.values.yaml declares id={region['id']!r}; the filename must match the id"); rc = 1
    rosters[name] = {p["id"]: p["replicationUrl"] for p in region.get("peers", [])}
    # A region absent from its own roster still works, but its peers would then
    # be pointing at a URL nobody validates here.
    if region["id"] not in rosters[name]:
        print(f"  \033[31mFAIL\033[0m {name} is missing itself from its own peers roster"); rc = 1

# Every region must agree on the whole mesh, or replication is one-directional.
if len(set(map(lambda r: tuple(sorted(r.items())), rosters.values()))) > 1:
    print("  \033[31mFAIL\033[0m peer rosters differ between regions:"); rc = 1
    for n, r in rosters.items():
        print(f"       {n}: {sorted(r.items())}")
elif rosters:
    print(f"  \033[32mok\033[0m   all {len(rosters)} regions share one roster of {len(next(iter(rosters.values())))} peers")

# Every region must hold the same shared-key Secret, or replicated ciphertext
# will not decrypt in the receiving region.
secrets = {n: (v.get("secrets") or {}).get("existingSecret") for n, v in regions.items()}
if len(set(secrets.values())) > 1 or None in secrets.values() or "" in secrets.values():
    print(f"  \033[31mFAIL\033[0m regions must share one secrets.existingSecret; got {secrets}"); rc = 1
else:
    print(f"  \033[32mok\033[0m   all regions read shared keys from {next(iter(secrets.values()))!r}")
sys.exit(rc)
PY

# ─────────────────────────────────────────────────────────────────────────────
note "chart lints and every region renders"
helm lint "$CHART" >/dev/null 2>&1 && ok "helm lint" || { bad "helm lint"; helm lint "$CHART" | sed 's/^/       /'; }

for f in "$GITOPS"/regions/*.values.yaml; do
  r="$(basename "$f" .values.yaml)"
  if helm template wslvault "$CHART" -n "wslvault-render-check" -f "$f" >"$OUT/$r.yaml" 2>"$OUT/$r.err"; then
    ok "$r renders ($(grep -c '^---' "$OUT/$r.yaml") documents)"
  else
    bad "$r failed to render:"; sed 's/^/       /' "$OUT/$r.err"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
note "rendered manifests are schema-valid"
if command -v kubeconform >/dev/null 2>&1; then
  for f in "$OUT"/*.yaml; do
    r="$(basename "$f" .yaml)"
    if kubeconform -strict -ignore-missing-schemas -summary "$f" >"$OUT/$r.kc" 2>&1; then
      ok "$r: $(tail -1 "$OUT/$r.kc")"
    else
      bad "$r failed validation:"; sed 's/^/       /' "$OUT/$r.kc"
    fi
  done
else
  echo "  kubeconform not installed; skipping schema validation"
fi

# ─────────────────────────────────────────────────────────────────────────────
note "regions run the same image for every component"
# Two regions in an active/active pair must run the same code. They drift
# silently: region A was pinned to newer builds while region B took the
# global.imageTag default, so four components differed — including
# secret-engine, where only region A carried the fix that lets External
# Secrets Operator validate the store. Failing the shared alias over to
# region B would have broken ESO cluster-wide, with nothing in Git saying so.
python3 - "$GITOPS" <<'IMGCHECK' || fail=1
import sys, pathlib, yaml, collections
gitops = pathlib.Path(sys.argv[1])
regions = {p.name.removesuffix(".values.yaml"): yaml.safe_load(p.read_text())
           for p in sorted((gitops / "regions").glob("*.values.yaml"))}

# Per-service image.tag, falling back to that region's global.imageTag.
tags = collections.defaultdict(dict)
for name, v in regions.items():
    default = ((v.get("global") or {}).get("imageTag")) or "<chart default>"
    for key, cfg in v.items():
        if isinstance(cfg, dict) and isinstance(cfg.get("image"), dict):
            tags[key][name] = cfg["image"].get("tag") or default

rc = 0
for svc, per_region in sorted(tags.items()):
    seen = {r: per_region.get(r, "<chart default>") for r in regions}
    if len(regions) > 1 and len(set(seen.values())) > 1:
        print(f"  \033[31mFAIL\033[0m {svc} differs across regions: "
              + ", ".join(f"{r}={v[:20]}" for r, v in sorted(seen.items())))
        rc = 1
if not rc:
    print(f"  \033[32mok\033[0m   pinned images match across {len(regions)} regions")
sys.exit(rc)
IMGCHECK

# ─────────────────────────────────────────────────────────────────────────────
note "no region ships a placeholder key"
# A region rendering REPLACE_ME_WITH_A_REAL_KEY would come up with a
# well-known root key, and — worse in a mesh — a DIFFERENT key per region, so
# replicated ciphertext would never decrypt.
if grep -rl "REPLACE_ME_WITH_A_REAL" "$OUT"/*.yaml >/dev/null 2>&1; then
  bad "placeholder key material rendered in: $(grep -rl 'REPLACE_ME_WITH_A_REAL' "$OUT"/*.yaml | xargs -n1 basename | tr '\n' ' ')"
  echo "       set secrets.existingSecret to the out-of-band mesh Secret"
else
  ok "all regions read key material from an external Secret"
fi

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32mAll GitOps checks passed.\033[0m\n'
else
  printf '\033[31mGitOps validation failed.\033[0m\n'
fi
exit "$fail"
