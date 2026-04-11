#!/usr/bin/env bash
# =============================================================================
# IamWatching — deploy.sh  v1.3.0
# =============================================================================
# Deploys the full IamWatching stack:
#   1. Validates prerequisites (Python 3.11+, Docker, Go)
#   2. Creates .venv and installs the Python package
#   3. Runs unit tests
#   4. Builds the Go daemon binary
#   5. Builds native PyInstaller executable  (opt-in: --native)
#   6. Builds Docker images
#   7. Starts Neo4j via Docker Compose
#   8. Applies Neo4j schema constraints
#   9. Generates start.sh / stop.sh / uninstall.sh then prints summary
#
# Usage:
#   ./deploy.sh                   # Standard deploy (no native build)
#   ./deploy.sh --native          # Also build PyInstaller binary
#   ./deploy.sh --skip-tests      # Skip pytest
#   ./deploy.sh --skip-docker     # Skip Docker steps
#   ./deploy.sh --skip-daemon     # Skip Go build
#   ./deploy.sh --dev             # Install dev extras
#   ./deploy.sh --log-level DEBUG
#   ./deploy.sh --log-dir /tmp/logs
#   ./deploy.sh --neo4j-password mypassword
#
# Env vars respected:
#   NEO4J_URI, NEO4J_PASSWORD, SKIP_TESTS, SKIP_DOCKER, PYINSTALLER_ONEFILE
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Portable millisecond clock
# macOS BSD date does NOT support %3N — use Python (always available here).
# ─────────────────────────────────────────────────────────────────────────────
_now_ms() { python3 -c "import time; print(int(time.time() * 1000))"; }
_elapsed() { echo $(( $(_now_ms) - $1 )); }

# ─────────────────────────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────────────────────────
RESET='\033[0m'; BOLD='\033[1m'
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; DIM='\033[2m'

# ─────────────────────────────────────────────────────────────────────────────
# Defaults (overridable via flags or env vars)
# ─────────────────────────────────────────────────────────────────────────────
SKIP_TESTS="${SKIP_TESTS:-0}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"
SKIP_DAEMON=0
SKIP_NATIVE=1          # OFF by default — must pass --native to enable
BUILD_NATIVE=0
DEV_INSTALL=0
LOG_LEVEL="INFO"
_LOG_DIR_ARG=""        # set only when --log-dir is explicitly passed
LOG_FILE=""
AUDIT_FILE=""
NEO4J_PASSWORD="${NEO4J_PASSWORD:-iamwatching}"
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
PYINSTALLER_ONEFILE="${PYINSTALLER_ONEFILE:-1}"

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --native)           BUILD_NATIVE=1; SKIP_NATIVE=0 ;;
        --skip-tests)       SKIP_TESTS=1 ;;
        --skip-docker)      SKIP_DOCKER=1 ;;
        --skip-daemon)      SKIP_DAEMON=1 ;;
        --skip-native)      SKIP_NATIVE=1; BUILD_NATIVE=0 ;;
        --dev)              DEV_INSTALL=1 ;;
        --log-level)        LOG_LEVEL="${2:-INFO}"; shift ;;
        --log-dir)          _LOG_DIR_ARG="${2:-}"; shift ;;
        --neo4j-password)   NEO4J_PASSWORD="$2"; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ===/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *)  echo -e "${YELLOW}[WARN]${RESET}  Unknown argument: $1 (ignored)" >&2 ;;
    esac
    shift
done

# ─────────────────────────────────────────────────────────────────────────────
# Resolve script location and cd FIRST — before any file I/O.
# This ensures that relative paths like "./logs" always resolve to the
# directory containing deploy.sh, regardless of where the user ran it from.
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Sanity check: warn if SCRIPT_DIR path has repeated "iamwatching" segments ──
_IW_COUNT=$(echo "$SCRIPT_DIR" | grep -o "iamwatching" | wc -l | tr -d ' ')
if [[ "$_IW_COUNT" -gt 2 ]]; then
    echo -e "${YELLOW}[WARN]${RESET}  deploy.sh appears to be nested inside multiple iamwatching/ folders." >&2
    echo -e "${YELLOW}[WARN]${RESET}  SCRIPT_DIR = $SCRIPT_DIR" >&2
    echo -e "${YELLOW}[WARN]${RESET}  Expected layout: IamWatching/iamwatching/deploy.sh" >&2
    echo -e "${YELLOW}[WARN]${RESET}  You may have extracted the tarball multiple times into the same folder." >&2
    echo -e "${YELLOW}[WARN]${RESET}  Hint: extract to a CLEAN directory: mkdir ~/IamWatching && cd ~/IamWatching && tar xzf iamwatching-v1.3.0.tar.gz" >&2
fi

# Resolve LOG_DIR: always derive from SCRIPT_DIR to avoid inheriting stale env vars.
if [[ -n "$_LOG_DIR_ARG" ]]; then
    # --log-dir was explicitly passed; make it absolute if needed
    if [[ "$_LOG_DIR_ARG" != /* ]]; then
        LOG_DIR="$SCRIPT_DIR/$_LOG_DIR_ARG"
    else
        LOG_DIR="$_LOG_DIR_ARG"
    fi
else
    # Default: always logs/ next to deploy.sh — never inherits from environment
    LOG_DIR="$SCRIPT_DIR/logs"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Init log files
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
_stamp=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOG_DIR/deploy-${_stamp}.jsonl"
AUDIT_FILE="$LOG_DIR/deploy-audit-${_stamp}.jsonl"

# ─────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────────────────────
_ts()      { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_lvlnum()  { case "$1" in DEBUG) echo 0;; INFO) echo 1;; WARN) echo 2;; *) echo 3;; esac; }

_jlog() {
    local lvl="$1" ev="$2" msg="${3//\"/\'}"; local dt="${4:-}"
    local j="{\"ts\":\"$(_ts)\",\"level\":\"$lvl\",\"event\":\"$ev\",\"message\":\"$msg\""
    [[ -n "$dt" ]] && j="$j,\"detail\":\"${dt//\"/\'}\""
    echo "$j}" >> "$LOG_FILE"
    if [[ "$lvl" == "WARN" || "$lvl" == "ERROR" ]]; then echo "$j}" >> "$AUDIT_FILE"; fi
}

log_debug() { [[ $(_lvlnum "$LOG_LEVEL") -le 0 ]] && echo -e "${DIM}[DEBUG] $1${RESET}" >&2 || true; _jlog "DEBUG" "STEP" "$1"; }
log_info()  { [[ $(_lvlnum "$LOG_LEVEL") -le 1 ]] && echo -e "${CYAN}[INFO]${RESET}  $1" >&2 || true;  _jlog "INFO"  "STEP" "$1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $1" >&2; _jlog "WARN"  "STEP" "$1"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $1" >&2;  _jlog "INFO"  "DONE" "$1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1" >&2;   _jlog "ERROR" "FAIL" "$1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}" >&2; _jlog "INFO" "STEP" "STEP: $1"; }
log_fatal() { log_error "$1"; echo -e "${RED}${BOLD}Deployment aborted.${RESET}" >&2; exit 1; }

run_cmd() {
    local label="$1"; shift
    local t0; t0=$(_now_ms)
    log_debug "$ $*"
    if "$@" >> "$LOG_FILE" 2>&1; then
        local ms; ms=$(_elapsed "$t0")
        log_ok "$label (${ms}ms)"
        echo "{\"ts\":\"$(_ts)\",\"level\":\"INFO\",\"event\":\"DONE\",\"step\":\"$label\",\"ms\":$ms}" >> "$AUDIT_FILE"
    else
        local rc=$?
        log_error "$label FAILED (exit $rc) — see $LOG_FILE"
        echo "{\"ts\":\"$(_ts)\",\"level\":\"ERROR\",\"event\":\"FAIL\",\"step\":\"$label\",\"rc\":$rc}" >> "$AUDIT_FILE"
        log_fatal "Aborting on command failure: $*"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat << 'BNREOF'
 ___            __        __    _       _     _
|_ _|__ _ _ __ \ \      / /_ _| |_ ___| |__ (_)_ __   __ _
 | |/ _` | '_ \ \ \ /\ / / _` | __/ __| '_ \| | '_ \ / _` |
 | | (_| | | | | \ V  V / (_| | || (__| | | | | | | | (_| |
|___\__,_|_| |_|  \_/\_/ \__,_|\__\___|_| |_|_|_| |_|\__, |
                                                        |___/
BNREOF
echo -e "${RESET}${DIM}Multi-Cloud IAM Security Auditor — Deployment v1.3.0${RESET}\n"

log_info "Deployment log : $LOG_FILE"
log_info "Audit log      : $AUDIT_FILE"
log_info "Log level      : $LOG_LEVEL"
log_info "Native build   : $([ "$SKIP_NATIVE" -eq 0 ] && echo 'YES (--native)' || echo 'NO  (pass --native to enable)')"

DEPLOY_START=$(_now_ms)
_jlog "INFO" "START" "Deployment started" "log_level=$LOG_LEVEL,native=$BUILD_NATIVE"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Prerequisites
# ─────────────────────────────────────────────────────────────────────────────
log_step "1 / 9  Checking prerequisites"

_check() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 not found in PATH"
        return 1
    fi
    local v; v=$("$1" --version 2>&1 | head -1) || true
    log_debug "$1: $v"
    log_ok "$1 available"
}

_check python3
_check pip3

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJ=${PY_VER%%.*}; PY_MIN=${PY_VER##*.}
if [[ "$PY_MAJ" -lt 3 || ( "$PY_MAJ" -eq 3 && "$PY_MIN" -lt 11 ) ]]; then
    log_fatal "Python 3.11+ required; found $PY_VER"
fi
log_ok "Python $PY_VER (>= 3.11 ✓)"

if [[ "$SKIP_DOCKER" -eq 0 ]]; then
    if ! command -v docker &>/dev/null; then
        log_warn "docker not found — Docker steps will be skipped"
        SKIP_DOCKER=1
    elif ! docker info &>/dev/null 2>&1; then
        log_warn "Docker daemon not running — Docker steps will be skipped"
        SKIP_DOCKER=1
    else
        log_ok "Docker available"
    fi
fi

if [[ "$SKIP_DAEMON" -eq 0 ]]; then
    if ! command -v go &>/dev/null; then
        log_warn "Go not found — daemon build will be skipped (get it at https://go.dev/dl/)"
        SKIP_DAEMON=1
    else
        GO_VER=$(go version | awk '{print $3}')
        log_ok "Go $GO_VER"
    fi
fi

_jlog "INFO" "DONE" "Prerequisites OK" "python=$PY_VER"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Python venv + package install
# ─────────────────────────────────────────────────────────────────────────────
log_step "2 / 9  Installing Python package"

VENV_DIR="$SCRIPT_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    log_info "Creating virtualenv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1
    log_ok "Virtualenv created"
else
    log_info "Reusing existing virtualenv at $VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

run_cmd "pip upgrade" pip install --upgrade pip

# Always install [dev] extras (pytest, pyinstaller).
# Cloud SDKs (aws/azure/gcp) are now in core dependencies and always installed.
EXTRAS="[dev]"

# Pre-flight: validate that pip can resolve the build system before full install
log_info "Pre-flight: checking build system ..."
if ! pip install --dry-run "setuptools>=68" "wheel" >> "$LOG_FILE" 2>&1; then
    log_warn "Build system pre-check failed — will attempt install anyway"
fi

log_info "Installing iamwatching${EXTRAS} ..."
log_info "This may take 2-5 minutes on first run (downloading cloud SDK deps) ..."
if ! pip install -e ".${EXTRAS}" >> "$LOG_FILE" 2>&1; then
    log_error "pip install failed. Last 40 lines of output:"
    echo "────────────────────────────────────────" >&2
    tail -40 "$LOG_FILE" >&2
    echo "────────────────────────────────────────" >&2
    log_fatal "Fix the install error above then re-run deploy.sh"
fi
log_ok "Package installed"

if ! command -v iamwatching &>/dev/null; then
    log_fatal "'iamwatching' CLI not found after install — check pyproject.toml [project.scripts]"
fi
IW_VER=$(iamwatching --version 2>&1 | head -1) || true
log_ok "iamwatching CLI: $IW_VER"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Tests
# ─────────────────────────────────────────────────────────────────────────────
log_step "3 / 9  Running tests"

if [[ "$SKIP_TESTS" -eq 1 ]]; then
    log_warn "Tests skipped (--skip-tests or SKIP_TESTS=1)"
else
    log_info "Running pytest (output shown in real time) ..."
    # Run pytest with live output to terminal AND log file simultaneously.
    # --timeout=30 kills any test hanging longer than 30s (requires pytest-timeout).
    # -x stops on first failure so you see the error immediately.
    # We install pytest-timeout if missing to prevent silent hangs.
    python3 -m pip install pytest-timeout --quiet >> "$LOG_FILE" 2>&1 || true

    # Use tee so output appears live on stderr AND gets written to the log file.
    # The exit code comes from pytest (via pipefail), not tee.
    set -o pipefail
    if python3 -m pytest tests/ -v --tb=short --timeout=30 2>&1 | tee -a "$LOG_FILE" >&2; then
        log_ok "All tests passed"
    else
        echo "" >&2
        log_fatal "Tests failed. See output above or re-run: ./deploy.sh --skip-tests"
    fi
    set +o pipefail
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Go daemon
# ─────────────────────────────────────────────────────────────────────────────
log_step "4 / 9  Building Go daemon"

DIST_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

if [[ "$SKIP_DAEMON" -eq 1 ]]; then
    log_warn "Daemon build skipped"
else
    DAEMON_DIR="$SCRIPT_DIR/daemon"
    DAEMON_OUT="$DIST_DIR/iamwatching-daemon"
    cd "$DAEMON_DIR"

    # Zero external dependencies — stdlib only, skip go mod download

    GOOS_NATIVE=$(go env GOOS)
    GOARCH_NATIVE=$(go env GOARCH)
    BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log_info "Building for ${GOOS_NATIVE}/${GOARCH_NATIVE} ..."
    run_cmd "go build" go build \
        -ldflags="-s -w -X main.Version=1.3.0 -X main.BuildTime=${BUILD_TIME}" \
        -o "$DAEMON_OUT" .

    # Cross-compile Linux amd64 binary for Docker (when on macOS)
    if [[ "$GOOS_NATIVE" == "darwin" ]]; then
        log_info "Cross-compiling Linux amd64 binary for Docker ..."
        GOOS=linux GOARCH=amd64 go build \
            -ldflags="-s -w -X main.Version=1.3.0" \
            -o "${DAEMON_OUT}-linux-amd64" . >> "$LOG_FILE" 2>&1 \
        && log_ok "Linux binary: dist/iamwatching-daemon-linux-amd64" \
        || log_warn "Linux cross-compile failed — Dockerfile will build from source instead"
    fi

    cd "$SCRIPT_DIR"
    SZ=$(du -sh "$DAEMON_OUT" | cut -f1)
    log_ok "Daemon built: dist/iamwatching-daemon ($SZ)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — PyInstaller native executable
# ─────────────────────────────────────────────────────────────────────────────
log_step "5 / 9  Building native executable (PyInstaller)"

if [[ "$SKIP_NATIVE" -eq 1 ]]; then
    log_warn "Native build skipped — re-run with --native to enable (adds ~2min)"
else
    SPEC_FILE="$SCRIPT_DIR/iamwatching.spec"
    NATIVE_OUT="$DIST_DIR/iamwatching"

    if ! python3 -c "import PyInstaller" &>/dev/null 2>&1; then
        log_info "Installing PyInstaller ..."
        run_cmd "pyinstaller install" pip install "pyinstaller>=6.8"
    fi

    if [[ ! -f "$SPEC_FILE" ]]; then
        log_fatal "iamwatching.spec not found at $SPEC_FILE"
    fi

    log_info "Running PyInstaller (1–3 min) ..."
    # Must run from SCRIPT_DIR so spec-relative paths (iamwatching/cli/main.py) resolve
    cd "$SCRIPT_DIR"
    PYI_FLAGS="--clean --noconfirm --onefile"
    PYI_FLAGS="$PYI_FLAGS --distpath $DIST_DIR"
    PYI_FLAGS="$PYI_FLAGS --workpath $SCRIPT_DIR/build"
    PYI_FLAGS="$PYI_FLAGS --specpath $SCRIPT_DIR"

    # Non-fatal: warn and continue if PyInstaller fails
    if python3 -m PyInstaller $PYI_FLAGS "$SPEC_FILE" >> "$LOG_FILE" 2>&1; then
        if [[ -f "$NATIVE_OUT" ]]; then
            chmod +x "$NATIVE_OUT"
            SZ=$(du -sh "$NATIVE_OUT" | cut -f1)
            log_ok "Native executable: dist/iamwatching ($SZ)"
            log_info "Run it with: ./dist/iamwatching audit --aws"
        else
            log_warn "PyInstaller finished but dist/iamwatching not found"
            log_warn "Check: ls -la $DIST_DIR/"
            ls -la "$DIST_DIR/" >> "$LOG_FILE" 2>&1 || true
        fi
    else
        log_warn "PyInstaller had errors (non-fatal) — check $LOG_FILE"
        log_warn "Common fixes: pip install pyinstaller --upgrade"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Docker images
# ─────────────────────────────────────────────────────────────────────────────
log_step "6 / 9  Building Docker images"

if [[ "$SKIP_DOCKER" -eq 1 ]]; then
    log_warn "Docker build skipped"
else
    run_cmd "docker build auditor" docker build \
        -t iamwatching-auditor:latest \
        -f docker/Dockerfile.auditor .

    if [[ "$SKIP_DAEMON" -eq 0 ]]; then
        run_cmd "docker build daemon" docker build \
            -t iamwatching-daemon:latest \
            -f docker/Dockerfile.daemon .
    fi
    log_ok "Docker images built"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Start Neo4j
# ─────────────────────────────────────────────────────────────────────────────
log_step "7 / 9  Starting Neo4j"

COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"

if [[ "$SKIP_DOCKER" -eq 1 ]]; then
    log_warn "Neo4j start skipped (Docker unavailable)"
else
    run_cmd "neo4j up" docker compose -f "$COMPOSE_FILE" up -d neo4j

    log_info "Waiting for Neo4j HTTP (up to 90s) ..."
    READY=0
    for i in $(seq 1 45); do
        if curl -sf "http://localhost:7474" &>/dev/null; then READY=1; break; fi
        log_debug "Not ready yet ($i/45) ..."
        sleep 2
    done

    if [[ "$READY" -eq 1 ]]; then
        log_ok "Neo4j ready"
        echo -e "  Browser : ${CYAN}http://localhost:7474${RESET}  (neo4j / $NEO4J_PASSWORD)"
        echo -e "  Bolt    : ${CYAN}bolt://localhost:7687${RESET}"
    else
        log_warn "Neo4j not ready after 90s — check: docker compose -f docker/docker-compose.yml logs neo4j"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Apply Neo4j constraints
# ─────────────────────────────────────────────────────────────────────────────
log_step "8 / 9  Applying Neo4j schema constraints"

python3 - <<PYEOF >> "$LOG_FILE" 2>&1 && log_ok "Neo4j constraints applied" || log_warn "Constraints will apply on first audit run (Neo4j may still be starting)"
import asyncio, os, sys
CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AWSPrincipal)    REQUIRE n.arn         IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AzurePrincipal)  REQUIRE n.object_id   IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:GCPPrincipal)    REQUIRE n.email       IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AWSResource)     REQUIRE n.arn         IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AzureResource)   REQUIRE n.resource_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:GCPResource)     REQUIRE n.resource_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:RoleDefinition)  REQUIRE n.role_id     IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:SAKey)           REQUIRE n.key_id      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:StateChangeEvent) REQUIRE n.timestamp  IS UNIQUE",
]
async def go():
    try:
        from neo4j import AsyncGraphDatabase
    except ImportError:
        print("neo4j driver not installed yet — skipping"); sys.exit(0)
    try:
        d = AsyncGraphDatabase.driver(
            os.environ.get("NEO4J_URI","bolt://localhost:7687"),
            auth=("neo4j", os.environ.get("NEO4J_PASSWORD","iamwatching"))
        )
        await d.verify_connectivity()
        async with d.session() as s:
            for c in CONSTRAINTS:
                try: await s.run(c); print(f"OK  {c[46:86]}")
                except Exception as e: print(f"SKP {e}")
        await d.close()
    except Exception as e:
        print(f"Neo4j unreachable: {e}"); sys.exit(0)
asyncio.run(go())
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — Generate start.sh / stop.sh / uninstall.sh  +  summary
# ─────────────────────────────────────────────────────────────────────────────
log_step "9 / 9  Generating management scripts + summary"

# ── start.sh ─────────────────────────────────────────────────────────────────
cat > "$SCRIPT_DIR/start.sh" << 'STARTEOF'
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
STARTEOF
chmod +x "$SCRIPT_DIR/start.sh"
log_ok "start.sh generated"

# ── stop.sh ───────────────────────────────────────────────────────────────────
cat > "$SCRIPT_DIR/stop.sh" << 'STOPEOF'
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
STOPEOF
chmod +x "$SCRIPT_DIR/stop.sh"
log_ok "stop.sh generated"

# ── uninstall.sh ──────────────────────────────────────────────────────────────
cat > "$SCRIPT_DIR/uninstall.sh" << 'UNINSTEOF'
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
UNINSTEOF
chmod +x "$SCRIPT_DIR/uninstall.sh"
log_ok "uninstall.sh generated"

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
TOTAL_MS=$(_elapsed "$DEPLOY_START")
TOTAL_S=$(( TOTAL_MS / 1000 ))

_jlog "INFO" "COMPLETE" "Deployment done" "duration_ms=$TOTAL_MS"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  IamWatching deployed in ${TOTAL_S}s${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Endpoints:${RESET}"
echo -e "  Neo4j Browser  ${CYAN}http://localhost:7474${RESET}  (neo4j / $NEO4J_PASSWORD)"
echo -e "  Neo4j Bolt     ${CYAN}bolt://localhost:7687${RESET}"
echo ""
echo -e "${BOLD}Deliverables:${RESET}"
if [[ -f "$SCRIPT_DIR/dist/iamwatching" ]]; then
    chmod +x "$SCRIPT_DIR/dist/iamwatching" 2>/dev/null || true
    echo -e "  Native CLI  ${CYAN}./dist/iamwatching${RESET}  (use this path, not ./iamwatching)"
fi
[[ -f "$SCRIPT_DIR/dist/iamwatching-daemon" ]] && echo -e "  Go Daemon   ${CYAN}dist/iamwatching-daemon${RESET}"
echo -e "  Python CLI  ${CYAN}iamwatching${RESET}  (activate .venv first)"
echo ""
echo -e "${BOLD}Management scripts:${RESET}"
echo -e "  ${CYAN}./start.sh${RESET}              Start Neo4j"
echo -e "  ${CYAN}./start.sh --daemon${RESET}     Start Neo4j + continuous Go poller"
echo -e "  ${CYAN}./stop.sh${RESET}               Stop all services"
echo -e "  ${CYAN}./uninstall.sh${RESET}          Remove everything (prompts first)"
echo -e "  ${CYAN}./uninstall.sh --yes${RESET}    Remove everything non-interactively"
echo ""
echo -e "${BOLD}Quick audit (venv):${RESET}"
echo -e "  source .venv/bin/activate"
echo -e "  iamwatching audit --aws --aws-regions us-east-1"
echo ""
if [[ -f "$SCRIPT_DIR/dist/iamwatching" ]]; then
    echo -e "${BOLD}Quick audit (native binary — no venv needed):${RESET}"
    echo -e "  ./dist/iamwatching audit --aws --aws-regions us-east-1"
    echo -e "  ${DIM}Note: run from inside the project folder, not ./iamwatching${RESET}"
fi
echo ""
echo -e "${BOLD}Logs:${RESET}"
echo -e "  ${DIM}$LOG_FILE${RESET}"
echo -e "  ${DIM}$AUDIT_FILE${RESET}"
echo ""
