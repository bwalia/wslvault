#!/usr/bin/env bash
# WSLVault Local Development Launcher
# Starts all backend services (Docker) and the Web UI (Next.js).
#
# Usage:
#   ./start-dev.sh          # Start everything
#   ./start-dev.sh stop     # Stop everything
#   ./start-dev.sh restart  # Restart everything
#   ./start-dev.sh status   # Show status
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
UI_DIR="$ROOT_DIR/ui/apps/vault-ui"
UI_PORT=3011
UI_PID_FILE="$ROOT_DIR/.ui.pid"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[wslvault]${NC} $*"; }
warn() { echo -e "${YELLOW}[wslvault]${NC} $*"; }
err()  { echo -e "${RED}[wslvault]${NC} $*" >&2; }

stop_ui() {
    if [[ -f "$UI_PID_FILE" ]]; then
        local pid
        pid=$(cat "$UI_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping UI (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$UI_PID_FILE"
    fi
    # Also kill any orphaned next-dev on our port
    lsof -ti:"$UI_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

stop_all() {
    log "Stopping all services..."
    stop_ui
    cd "$ROOT_DIR"
    docker compose down 2>&1 | grep -v "level=warning"
    log "All services stopped."
}

start_backend() {
    log "Starting backend services (Docker Compose)..."
    cd "$ROOT_DIR"
    docker compose up -d 2>&1 | grep -v "level=warning"

    # Wait for postgres to be healthy
    log "Waiting for PostgreSQL..."
    local retries=0
    while ! docker compose exec -T postgres pg_isready -U wslvault -q 2>/dev/null; do
        retries=$((retries + 1))
        if [[ $retries -ge 30 ]]; then
            err "PostgreSQL did not become ready in 30s"
            exit 1
        fi
        sleep 1
    done
    log "PostgreSQL is ready."

    # Wait for gateway to respond
    log "Waiting for gateway (port 8088)..."
    retries=0
    while ! curl -sf http://localhost:8088/health >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [[ $retries -ge 30 ]]; then
            err "Gateway did not become ready in 30s"
            exit 1
        fi
        sleep 1
    done
    log "Gateway is ready at http://localhost:8088"
}

start_ui() {
    stop_ui  # Kill any stale process

    if [[ ! -d "$UI_DIR/node_modules" ]]; then
        log "Installing UI dependencies..."
        cd "$UI_DIR" && npm install
    fi

    log "Starting Web UI on port $UI_PORT..."
    cd "$UI_DIR"
    npx next dev --turbopack -p "$UI_PORT" -H 0.0.0.0 > "$ROOT_DIR/.ui.log" 2>&1 &
    echo $! > "$UI_PID_FILE"

    # Wait for UI to respond
    local retries=0
    while ! curl -sf http://localhost:$UI_PORT/ >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [[ $retries -ge 30 ]]; then
            err "UI did not start in 30s. Check $ROOT_DIR/.ui.log"
            exit 1
        fi
        sleep 1
    done
    log "Web UI is ready at http://localhost:$UI_PORT"
}

show_status() {
    echo ""
    log "=== Service Status ==="
    echo ""

    # Docker services
    cd "$ROOT_DIR"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>&1 | grep -v "level=warning"

    echo ""

    # UI
    if [[ -f "$UI_PID_FILE" ]] && kill -0 "$(cat "$UI_PID_FILE")" 2>/dev/null; then
        log "Web UI: ${GREEN}running${NC} (PID $(cat "$UI_PID_FILE")) at http://localhost:$UI_PORT"
    else
        warn "Web UI: ${RED}not running${NC}"
    fi

    echo ""
    log "=== Endpoints ==="
    echo "  Gateway API:  http://localhost:8088"
    echo "  Web UI:       http://localhost:$UI_PORT"
    echo "  Grafana:      http://localhost:3000  (admin / wslvault-dev)"
    echo "  Prometheus:   http://localhost:9090"
    echo ""
}

case "${1:-start}" in
    start)
        start_backend
        start_ui
        show_status
        ;;
    stop)
        stop_all
        ;;
    restart)
        stop_all
        sleep 2
        start_backend
        start_ui
        show_status
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
