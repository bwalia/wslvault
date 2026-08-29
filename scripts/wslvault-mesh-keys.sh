#!/usr/bin/env bash
# Create or rotate the shared key material every wslvault region must hold.
#
# WHY THIS IS ONE SECRET IN EVERY REGION, NOT ONE PER REGION
#   region B decrypts ciphertext that region A encrypted, using its OWN root
#   key — so the root keys must be identical. A token minted by region A's
#   identity-service is verified by region B's secret-engine with its own JWT
#   secret — identical too. Peers authenticate to each other's replication API
#   with a shared bearer token. Generate these per region and the mesh looks
#   healthy while silently failing to replicate anything usable.
#
#   The keys never live in Git. This script writes them straight into each
#   region's namespace; the values files only reference the Secret by name.
#
# Usage:
#   ./scripts/wslvault-mesh-keys.sh adopt <namespace> [--release NAME]
#   ./scripts/wslvault-mesh-keys.sh create   [--dry-run]
#   ./scripts/wslvault-mesh-keys.sh copy-from <source-namespace>
#   ./scripts/wslvault-mesh-keys.sh verify
#
#   adopt       Consolidate a region's EXISTING per-key Secrets
#               (<release>-root-key, -jwt-secret, -pki-root-key) into the mesh
#               Secret, preserving the exact key bytes. This is the path for
#               the first region: it already holds encrypted data, so its root
#               key must survive the move unchanged.
#   create      Generate fresh material and install it in every region. For a
#               mesh with no data yet. Refuses to overwrite an existing Secret
#               — a new root key makes every stored secret undecryptable.
#   copy-from   Copy one region's mesh Secret into the others (this is how a
#               new region joins a live mesh).
#   verify      Check that every region holds byte-identical material.
#
# Env:
#   KUBECONFIG   as usual
#   NAMESPACES   space-separated region namespaces
#                (default: "wslvault wslvault-b")
#   SECRET_NAME  default: wslvault-mesh-keys
set -euo pipefail

SECRET_NAME="${SECRET_NAME:-wslvault-mesh-keys}"
NAMESPACES="${NAMESPACES:-wslvault wslvault-b}"
DRY_RUN=""

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# The four keys the chart reads out of this Secret. Key names match
# secrets.existingSecretKeys in values.yaml.
apply_secret() {
  local ns="$1" root="$2" jwt="$3" pki="$4" peer="$5"
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$ns" create secret generic "$SECRET_NAME" \
    --from-literal=root-key="$root" \
    --from-literal=jwt-secret="$jwt" \
    --from-literal=pki-root-key="$pki" \
    --from-literal=replication-peer-token="$peer" \
    --dry-run=client -o yaml | kubectl apply $DRY_RUN -f -
}

cmd_adopt() {
  local ns="${1:-}" release="${RELEASE:-wslvault}"
  [ -n "$ns" ] || die "usage: $0 adopt <namespace> [--release NAME]"

  note "adopting existing key material from $ns (release $release)"

  # Read the keys the running region is ALREADY using. Generating new ones here
  # would orphan every secret it has encrypted so far.
  local root jwt pki
  root="$(kubectl -n "$ns" get secret "${release}-root-key" -o jsonpath='{.data.root-key}' 2>/dev/null | base64 -d)" \
    || die "${release}-root-key not found in $ns"
  jwt="$(kubectl -n "$ns" get secret "${release}-jwt-secret" -o jsonpath='{.data.jwt-secret}' 2>/dev/null | base64 -d)" \
    || die "${release}-jwt-secret not found in $ns"
  pki="$(kubectl -n "$ns" get secret "${release}-pki-root-key" -o jsonpath='{.data.pki-root-key}' 2>/dev/null | base64 -d)"

  [ -n "$root" ] || die "${release}-root-key in $ns has an empty root-key"
  [ -n "$jwt" ]  || die "${release}-jwt-secret in $ns has an empty jwt-secret"

  case "$root" in
    REPLACE_ME_WITH_A_REAL*) die "$ns is running with the chart's PLACEHOLDER root key.
       Adopting it would carry that placeholder into every region. Replace the
       key in $ns first (and re-encrypt any stored secrets)." ;;
  esac

  # The peer token is new — no existing region has one — so mint it here.
  local peer
  peer="$(openssl rand -hex 32)"

  for target in $NAMESPACES; do
    apply_secret "$target" "$root" "$jwt" "$pki" "$peer"
    printf '  installed in %s\n' "$target"
  done
  note "done — the mesh now uses ${ns}'s existing keys, so its data stays readable"
}

cmd_create() {
  for ns in $NAMESPACES; do
    if kubectl -n "$ns" get secret "$SECRET_NAME" >/dev/null 2>&1; then
      die "$SECRET_NAME already exists in namespace $ns.
       Rotating the root key makes every secret already stored in the mesh
       undecryptable. To add a region to a live mesh use:
         $0 copy-from $ns"
    fi
  done

  note "generating shared mesh key material"
  # 32 bytes for the AES-256 keys, 64 for the HS256 signing secret, 32 for the
  # peer bearer token.
  local root jwt pki peer
  root="$(openssl rand -base64 32)"
  jwt="$(openssl rand -base64 64 | tr -d '\n')"
  pki="$(openssl rand -base64 32)"
  peer="$(openssl rand -hex 32)"

  for ns in $NAMESPACES; do
    apply_secret "$ns" "$root" "$jwt" "$pki" "$peer"
    printf '  installed in %s\n' "$ns"
  done
  note "done — every region now holds identical key material"
}

cmd_copy_from() {
  local src="${1:-}"
  [ -n "$src" ] || die "usage: $0 copy-from <source-namespace>"
  kubectl -n "$src" get secret "$SECRET_NAME" >/dev/null 2>&1 \
    || die "$SECRET_NAME not found in namespace $src"

  note "copying $SECRET_NAME from $src"
  local root jwt pki peer
  root="$(kubectl -n "$src" get secret "$SECRET_NAME" -o jsonpath='{.data.root-key}' | base64 -d)"
  jwt="$(kubectl -n "$src" get secret "$SECRET_NAME" -o jsonpath='{.data.jwt-secret}' | base64 -d)"
  pki="$(kubectl -n "$src" get secret "$SECRET_NAME" -o jsonpath='{.data.pki-root-key}' | base64 -d)"
  peer="$(kubectl -n "$src" get secret "$SECRET_NAME" -o jsonpath='{.data.replication-peer-token}' | base64 -d)"

  # A region joining a mesh whose source Secret predates the peer token would
  # otherwise get an empty token and fail closed on every peer poll.
  if [ -z "$peer" ]; then
    peer="$(openssl rand -hex 32)"
    printf '  source has no replication-peer-token; generating one and\n'
    printf '  writing it back to %s as well\n' "$src"
    apply_secret "$src" "$root" "$jwt" "$pki" "$peer"
  fi

  for ns in $NAMESPACES; do
    [ "$ns" = "$src" ] && continue
    apply_secret "$ns" "$root" "$jwt" "$pki" "$peer"
    printf '  installed in %s\n' "$ns"
  done
  note "done"
}

cmd_verify() {
  note "comparing key material across regions"
  local ref="" refns="" rc=0
  for ns in $NAMESPACES; do
    if ! kubectl -n "$ns" get secret "$SECRET_NAME" >/dev/null 2>&1; then
      printf '  \033[31mFAIL\033[0m %s: %s is missing\n' "$ns" "$SECRET_NAME"; rc=1; continue
    fi
    # Fingerprint rather than print: the point is to compare, not to disclose.
    local fp
    fp="$(kubectl -n "$ns" get secret "$SECRET_NAME" \
          -o jsonpath='{.data.root-key}{.data.jwt-secret}{.data.pki-root-key}{.data.replication-peer-token}' \
          | shasum -a 256 | cut -c1-16)"
    if [ -z "$ref" ]; then
      ref="$fp"; refns="$ns"
      printf '  %s: %s\n' "$ns" "$fp"
    elif [ "$fp" = "$ref" ]; then
      printf '  \033[32mok\033[0m   %s: matches %s\n' "$ns" "$refns"
    else
      printf '  \033[31mFAIL\033[0m %s: %s differs from %s (%s)\n' "$ns" "$fp" "$refns" "$ref"
      printf '       replicated ciphertext will not decrypt between these regions\n'
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] && printf '\n\033[32mAll regions hold identical key material.\033[0m\n'
  return "$rc"
}

case "${1:-}" in
  adopt)      shift
              ns="${1:-}"; shift || true
              if [ "${1:-}" = "--release" ]; then RELEASE="${2:-}"; fi
              cmd_adopt "$ns" ;;
  create)     shift; [ "${1:-}" = "--dry-run" ] && DRY_RUN="--dry-run=client"; cmd_create ;;
  copy-from)  shift; cmd_copy_from "${1:-}" ;;
  verify)     cmd_verify ;;
  *) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
