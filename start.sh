#!/usr/bin/env bash
# Drive the local WSLVault stack: start | stop | restart | status | logs.
#
# The local stack is ten containers created by hand with `docker run` against
# bind-mounted source — not a compose project. `docker compose ps` prints
# nothing for it, and `docker compose up` would create a *second*, differently
# named set rather than adopting these. So this drives them by name, and
# start/stop/restart reuse the containers with the env, mounts and ports they
# were created with.
#
# Usage:
#   ./start.sh            # same as start
#   ./start.sh stop
#   ./start.sh restart
#   ./start.sh status
#   ./start.sh logs wv-ui   # follow one container (ctrl-C to detach)
set -euo pipefail

# Start order: Postgres first because every service connects to it on boot, and
# the UI last because it is the only thing a person waits on.
CONTAINERS=(wv-pg wv-crypto wv-identity wv-secret wv-policy wv-lease wv-transit wv-region wv-audit wv-ui)

UI_URL="http://127.0.0.1:3012/login"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

docker info >/dev/null 2>&1 || die "Docker is not running — start Docker Desktop first."

# Report containers that do not exist rather than failing halfway through.
# These are created by hand, so a missing one means it was removed, and
# `docker start` cannot recreate it.
missing=()
for c in "${CONTAINERS[@]}"; do
  docker container inspect "$c" >/dev/null 2>&1 || missing+=("$c")
done
if ((${#missing[@]})); then
  warn "not found, skipping: ${missing[*]}"
  warn "these were created with 'docker run'; recreate them the same way."
fi

exists() { docker container inspect "$1" >/dev/null 2>&1; }

start_stack() {
  bold "Starting"
  for c in "${CONTAINERS[@]}"; do
    exists "$c" || continue
    if [[ "$(docker inspect -f '{{.State.Running}}' "$c")" == "true" ]]; then
      echo "  $c already running"
    else
      docker start "$c" >/dev/null && echo "  $c"
    fi
  done

  # The UI is a Next.js dev server: the container is "running" long before it
  # has compiled and bound the port. Waiting here is the difference between
  # "the stack is up" and a connection-refused that looks like a broken build.
  printf '\nWaiting for the UI to compile'
  for _ in $(seq 1 60); do
    if curl -sS -o /dev/null --max-time 5 "$UI_URL" 2>/dev/null; then
      printf '\n\n'
      bold "Ready"
      echo "  UI        http://localhost:3012"
      echo "  identity  http://localhost:18082"
      return 0
    fi
    printf '.'
    sleep 2
  done
  printf '\n'
  warn "UI did not answer within 120s — check: ./start.sh logs wv-ui"
}

stop_stack() {
  bold "Stopping"
  # Reverse order: take the front door down first so nothing is mid-request
  # when Postgres goes.
  for ((i = ${#CONTAINERS[@]} - 1; i >= 0; i--)); do
    c="${CONTAINERS[i]}"
    exists "$c" || continue
    docker stop "$c" >/dev/null && echo "  $c"
  done
}

status_stack() {
  bold "Status"
  for c in "${CONTAINERS[@]}"; do
    if exists "$c"; then
      printf '  %-14s %s\n' "$c" "$(docker inspect -f '{{.State.Status}}' "$c")"
    else
      printf '  %-14s %s\n' "$c" "missing"
    fi
  done
}

case "${1:-start}" in
  start)   start_stack ;;
  stop)    stop_stack ;;
  restart) stop_stack; echo; start_stack ;;
  status)  status_stack ;;
  logs)
    [[ $# -ge 2 ]] || die "which container? e.g. ./start.sh logs wv-ui"
    exists "$2" || die "no such container: $2"
    docker logs -f --tail 100 "$2"
    ;;
  *) die "unknown command '$1' — use: start | stop | restart | status | logs <container>" ;;
esac
