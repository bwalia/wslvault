#!/usr/bin/env bash
# Guards one property of wslvault-mesh-keys.sh: `apply_secret` must carry
# `smtp-password` and `admin-token` through a re-run.
#
# Why this exists: the Secret is written with `kubectl create secret generic
# ... | kubectl apply -f -`, which replaces `data` wholesale. Those two keys are
# deployment config rather than mesh material, so the script does not generate
# them — and before they were carried forward, any re-run of adopt/create/
# copy-from silently switched off invitation email (SMTP_PASSWORD) and the
# bootstrap admin token (VAULT_ADMIN_TOKEN) in a live region.
#
# Runs offline against a stubbed kubectl. No cluster, no credentials.
#
# Usage: scripts/test-mesh-keys-preservation.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/wslvault-mesh-keys.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
cat >"$TMP/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"create namespace"*) echo "apiVersion: v1"; exit 0 ;;
  *"apply -f -"*)       cat >/dev/null; exit 0 ;;
  *"jsonpath={.data.smtp-password}"*)
      [ -n "${EXISTING_SMTP:-}" ] && printf %s "$EXISTING_SMTP" | base64 || true; exit 0 ;;
  *"jsonpath={.data.admin-token}"*)
      [ -n "${EXISTING_ADMIN:-}" ] && printf %s "$EXISTING_ADMIN" | base64 || true; exit 0 ;;
  *"jsonpath={.data.root-key}"*)               printf %s ROOT  | base64; exit 0 ;;
  *"jsonpath={.data.jwt-secret}"*)             printf %s JWT   | base64; exit 0 ;;
  *"jsonpath={.data.pki-root-key}"*)           printf %s PKI   | base64; exit 0 ;;
  *"jsonpath={.data.replication-peer-token}"*) printf %s PEER  | base64; exit 0 ;;
  *"jsonpath={.data.audit-signing-key}"*)      printf %s AUDIT | base64; exit 0 ;;
  *"get secret"*)            exit 0 ;;
  *"create secret generic"*) printf '%s\n' "$args" >>"$CAPTURE"; echo "kind: Secret"; exit 0 ;;
esac
exit 0
STUB
chmod +x "$TMP/bin/kubectl"

fails=0
check() { # check <label> <expected-smtp> <expected-admin>
  local label="$1" want_smtp="$2" want_admin="$3" got_smtp got_admin
  export CAPTURE="$TMP/cap"; : >"$CAPTURE"
  PATH="$TMP/bin:$PATH" NAMESPACES="target" SECRET_NAME="wslvault-mesh-keys" \
    bash "$TARGET" copy-from source >/dev/null 2>&1
  got_smtp="$(grep -o 'smtp-password=[^ ]*' "$CAPTURE" | head -1 | cut -d= -f2-)"
  got_admin="$(grep -o 'admin-token=[^ ]*' "$CAPTURE" | head -1 | cut -d= -f2-)"
  if [ "$got_smtp" = "$want_smtp" ] && [ "$got_admin" = "$want_admin" ]; then
    printf '  ok    %s\n' "$label"
  else
    printf '  FAIL  %s\n        smtp: want %-14s got %s\n        admin: want %-13s got %s\n' \
      "$label" "'$want_smtp'" "'$got_smtp'" "'$want_admin'" "'$got_admin'"
    fails=$((fails + 1))
  fi
}

printf 'apply_secret key preservation\n'
EXISTING_SMTP=PRESERVED_PW EXISTING_ADMIN=PRESERVED_TOK \
  check "existing keys survive a re-run" PRESERVED_PW PRESERVED_TOK
SMTP_PASSWORD=ENV_PW VAULT_ADMIN_TOKEN=ENV_TOK \
  check "environment seeds a first value" ENV_PW ENV_TOK
EXISTING_SMTP=OLD_PW SMTP_PASSWORD=NEW_PW \
  check "environment overrides what is stored" NEW_PW ""
check "absent on both sides stays empty" "" ""

[ "$fails" -eq 0 ] || { printf '\n%d check(s) failed\n' "$fails"; exit 1; }
printf '\nall checks passed\n'
