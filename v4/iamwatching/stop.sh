#!/usr/bin/env bash
# =============================================================================
# IamWatching — stop.sh
# Gracefully stops the Go daemon and Neo4j container.
#
# Usage:
#   ./stop.sh               Stop daemon + Neo4j
#   ./stop.sh --daemon-only Stop daemon only, leave Neo4j running
#   ./stop.sh --neo4j-only  Stop Neo4j only, leave daemon running
# =============================================================================
set -euo pipefail
RESET='\033[0m'; BOLD='\033[1m'; CYAN='\033[0;36m'
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
PID_FILE="$SCRIPT_DIR/.daemon.pid"

STOP_DAEMON=1
STOP_NEO4J=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon-only)  STOP_NEO4J=0 ;;
        --neo4j-only)   STOP_DAEMON=0 ;;
        --help|-h) echo "Usage: $0 [--daemon-only | --neo4j-only]"; exit 0 ;;
        *) log_warn "Unknown argument: $1" ;;
    esac
    shift
done

echo -e "${BOLD}${CYAN} IamWatching — Stopping Services${RESET}\n"

# ── Daemon ────────────────────────────────────────────────────────────────────
if [[ "$STOP_DAEMON" -eq 1 ]]; then
    log_step "Go Daemon"
    if [[ -f "$PID_FILE" ]]; then
        DPID=$(cat "$PID_FILE")
        if kill -0 "$DPID" 2>/dev/null; then
            log_info "Sending SIGTERM to PID $DPID ..."
            kill -TERM "$DPID"
            for i in $(seq 1 10); do
                kill -0 "$DPID" 2>/dev/null || break
                sleep 1
            done
            if kill -0 "$DPID" 2>/dev/null; then
                log_warn "Daemon did not exit cleanly — sending SIGKILL"
                kill -KILL "$DPID" 2>/dev/null || true
            fi
            log_ok "Daemon stopped (was PID $DPID)"
        else
            log_warn "PID $DPID not running (stale .daemon.pid)"
        fi
        rm -f "$PID_FILE"
    else
        log_warn "No .daemon.pid found — daemon may not be running"
    fi
fi

# ── Neo4j ─────────────────────────────────────────────────────────────────────
if [[ "$STOP_NEO4J" -eq 1 ]]; then
    log_step "Neo4j"
    if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
        log_warn "Docker not available — cannot stop container"
    else
        if docker compose -f "$COMPOSE_FILE" ps --services --filter status=running 2>/dev/null | grep -q neo4j; then
            docker compose -f "$COMPOSE_FILE" stop neo4j
            log_ok "Neo4j stopped (graph data preserved in Docker volume)"
        else
            log_warn "Neo4j is not running"
        fi
    fi
fi

echo ""
echo -e "  Restart : ${CYAN}./start.sh${RESET}"
echo ""
