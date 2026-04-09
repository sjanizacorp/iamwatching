#!/usr/bin/env bash
# =============================================================================
# IamWatching — uninstall.sh
# Removes all IamWatching components from this machine.
# Stops services, removes Docker containers/volumes/images,
# deletes the venv, dist/, build/, and optionally logs/.
#
# Usage:
#   ./uninstall.sh              Interactive (prompts before data deletion)
#   ./uninstall.sh --yes        Non-interactive (delete everything)
#   ./uninstall.sh --keep-data  Preserve Neo4j Docker volume (keep graph)
#   ./uninstall.sh --keep-logs  Preserve log files
# =============================================================================
set -euo pipefail
RESET='\033[0m'; BOLD='\033[1m'; CYAN='\033[0;36m'
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"
PID_FILE="$SCRIPT_DIR/.daemon.pid"

YES=0; KEEP_DATA=0; KEEP_LOGS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)       YES=1 ;;
        --keep-data)    KEEP_DATA=1 ;;
        --keep-logs)    KEEP_LOGS=1 ;;
        --help|-h) echo "Usage: $0 [--yes] [--keep-data] [--keep-logs]"; exit 0 ;;
        *) log_warn "Unknown argument: $1" ;;
    esac
    shift
done

echo -e "${BOLD}${RED}"
cat << 'ARTEOF'
 _   _ _   _ ___ _   _ ____ _____  _    _     _
| | | | \ | |_ _| \ | / ___|_   _|/ \  | |   | |
| | | |  \| || ||  \| \___ \ | | / _ \ | |   | |
| |_| | |\  || || |\  |___) || |/ ___ \| |___| |___
 \___/|_| \_|___|_| \_|____/ |_/_/   \_\_____|_____|
ARTEOF
echo -e "${RESET}"
echo -e "${BOLD}This will remove IamWatching from this machine.${RESET}\n"

if [[ "$YES" -eq 0 ]]; then
    echo -e "${YELLOW}Will remove:${RESET}"
    echo "  • Go daemon process (if running)"
    echo "  • Neo4j container"
    [[ "$KEEP_DATA" -eq 0 ]] && echo -e "  • ${RED}Neo4j volume — ALL GRAPH DATA DELETED${RESET}"
    echo "  • Docker images: iamwatching-auditor, iamwatching-daemon"
    echo "  • Python virtualenv (.venv/)"
    echo "  • Compiled binaries (dist/)"
    echo "  • PyInstaller build cache (build/)"
    [[ "$KEEP_LOGS" -eq 0 ]] && echo "  • Log files (logs/)"
    echo ""
    read -r -p "Continue? [y/N] " _confirm
    [[ "$_confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
fi

# 1. Stop services
log_step "Stopping services"
if [[ -f "$PID_FILE" ]]; then
    DPID=$(cat "$PID_FILE")
    if kill -0 "$DPID" 2>/dev/null; then
        log_info "Stopping daemon PID $DPID ..."
        kill -TERM "$DPID" 2>/dev/null || true; sleep 2
        kill -KILL "$DPID" 2>/dev/null || true
        log_ok "Daemon stopped"
    fi
    rm -f "$PID_FILE"
else
    log_info "No daemon PID file — skipping"
fi

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    log_ok "Neo4j container stopped"
else
    log_warn "Docker unavailable — containers not stopped"
fi

# 2. Docker volumes
if [[ "$KEEP_DATA" -eq 0 ]]; then
    log_step "Removing Neo4j graph data"
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
        docker volume rm iamwatching_neo4j_data iamwatching_neo4j_logs \
                         iamwatching_neo4j_plugins 2>/dev/null || true
        log_ok "Neo4j volumes removed"
    else
        log_warn "Docker unavailable — volumes may remain"
    fi
else
    log_warn "Neo4j volumes preserved (--keep-data)"
fi

# 3. Docker images
log_step "Removing Docker images"
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    for img in iamwatching-auditor:latest iamwatching-daemon:latest; do
        if docker image inspect "$img" &>/dev/null 2>&1; then
            docker rmi "$img" && log_ok "Removed: $img" || log_warn "Could not remove $img"
        else
            log_info "Image not present: $img"
        fi
    done
else
    log_warn "Docker unavailable — images not removed"
fi

# 4. Virtualenv
log_step "Removing Python virtualenv"
if [[ -d "$SCRIPT_DIR/.venv" ]]; then
    rm -rf "$SCRIPT_DIR/.venv"; log_ok "Removed: .venv/"
else
    log_info ".venv not found"
fi

# 5. Build artifacts
log_step "Removing compiled binaries and build cache"
[[ -d "$SCRIPT_DIR/dist"  ]] && { rm -rf "$SCRIPT_DIR/dist";  log_ok "Removed: dist/"; }  || log_info "dist/ not found"
[[ -d "$SCRIPT_DIR/build" ]] && { rm -rf "$SCRIPT_DIR/build"; log_ok "Removed: build/"; } || log_info "build/ not found"
find "$SCRIPT_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -name "*.pyc"       -delete 2>/dev/null || true
log_ok "Python bytecode cache cleared"

# 6. Logs
if [[ "$KEEP_LOGS" -eq 0 ]]; then
    log_step "Removing log files"
    if [[ -d "$SCRIPT_DIR/logs" ]]; then
        rm -rf "$SCRIPT_DIR/logs"; log_ok "Removed: logs/"
    else
        log_info "logs/ not found"
    fi
else
    log_warn "Log files preserved (--keep-logs)"
fi

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  IamWatching uninstalled successfully${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Source code remains in : ${CYAN}$SCRIPT_DIR${RESET}"
echo -e "  To reinstall           : ${CYAN}./deploy.sh${RESET}"
echo ""
