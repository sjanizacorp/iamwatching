#!/usr/bin/env bash
# =============================================================================
# IamWatching — start.sh
# Starts Neo4j and optionally the continuous Go daemon.
#
# Usage:
#   ./start.sh                          Start Neo4j only
#   ./start.sh --daemon                 Start Neo4j + Go daemon
#   ./start.sh --daemon --poll-interval 120
# =============================================================================
set -euo pipefail
RESET='\033[0m'; BOLD='\033[1m'; CYAN='\033[0;36m'
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
DAEMON_BIN="$SCRIPT_DIR/dist/iamwatching-daemon"
VENV="$SCRIPT_DIR/.venv/bin/activate"
DAEMON_PID_FILE="$SCRIPT_DIR/.daemon.pid"

START_DAEMON=0
POLL_INTERVAL=300

while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon)           START_DAEMON=1 ;;
        --poll-interval)    POLL_INTERVAL="$2"; shift ;;
        --help|-h) echo "Usage: $0 [--daemon] [--poll-interval SECONDS]"; exit 0 ;;
        *) log_warn "Unknown argument: $1" ;;
    esac
    shift
done

echo -e "${BOLD}${CYAN} IamWatching — Starting Services${RESET}\n"

# ── Neo4j ─────────────────────────────────────────────────────────────────────
log_step "Neo4j"
if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    log_error "Docker is not running — start Docker Desktop and retry"
    exit 1
fi

log_info "Starting Neo4j container ..."
docker compose -f "$COMPOSE_FILE" up -d neo4j

log_info "Waiting for Neo4j (up to 90s) ..."
READY=0
for i in $(seq 1 45); do
    if curl -sf "http://localhost:7474" &>/dev/null; then READY=1; break; fi
    sleep 2
done
if [[ "$READY" -eq 1 ]]; then
    log_ok "Neo4j ready"
    echo -e "  Browser : ${CYAN}http://localhost:7474${RESET}  (neo4j / iamwatching)"
    echo -e "  Bolt    : ${CYAN}bolt://localhost:7687${RESET}"
else
    log_warn "Neo4j may not be ready — check: docker compose logs neo4j"
fi

# ── Python venv ───────────────────────────────────────────────────────────────
if [[ -f "$VENV" ]]; then
    # shellcheck source=/dev/null
    source "$VENV"
    log_ok "Python venv activated"
else
    log_warn ".venv not found — run ./deploy.sh first"
fi

# ── Go Daemon (optional) ──────────────────────────────────────────────────────
if [[ "$START_DAEMON" -eq 1 ]]; then
    log_step "Go Daemon"

    if [[ ! -f "$DAEMON_BIN" ]]; then
        log_error "Daemon binary not found: $DAEMON_BIN"
        log_error "Run: ./deploy.sh --skip-tests --skip-docker --skip-native"
        exit 1
    fi

    if [[ -f "$DAEMON_PID_FILE" ]]; then
        OLD_PID=$(cat "$DAEMON_PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            log_warn "Daemon already running (PID $OLD_PID) — run ./stop.sh first"
            exit 0
        fi
        rm -f "$DAEMON_PID_FILE"
    fi

    mkdir -p "$SCRIPT_DIR/logs"
    DAEMON_LOG="$SCRIPT_DIR/logs/daemon.log"

    nohup "$DAEMON_BIN" \
        --poll-interval "$POLL_INTERVAL" \
        --neo4j "bolt://localhost:7687" \
        --log-level info \
        >> "$DAEMON_LOG" 2>&1 &

    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$DAEMON_PID_FILE"
    sleep 1

    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        log_ok "Daemon started (PID $DAEMON_PID, polling every ${POLL_INTERVAL}s)"
        echo -e "  Log : ${CYAN}$DAEMON_LOG${RESET}"
        echo -e "  PID : $DAEMON_PID  (saved in .daemon.pid)"
    else
        log_error "Daemon exited immediately — check $DAEMON_LOG"
        exit 1
    fi
fi

echo ""
log_step "Ready"
echo -e "  Venv audit   : ${CYAN}iamwatching audit --aws${RESET}    (activate .venv first)"
echo -e "  Native audit : ${CYAN}./dist/iamwatching audit --aws${RESET}  (no venv needed)"
echo -e "  Stop all     : ${CYAN}./stop.sh${RESET}"
echo ""
