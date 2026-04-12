# IamWatching — Master Build Prompt
> **Version:** 1.2.0 | **Author:** Aniza Corp Security Research
> Copy this prompt verbatim to recreate the full IamWatching stack from scratch.

---

## Prompt

Act as a world-class IAM security researcher and developer. Build **IamWatching v1.1.0**, a production-grade multi-cloud (AWS, Azure, GCP) IAM security auditor named after a real-world threat intelligence concept. The tool must be structured as an installable Python package with the following six primary components, plus four supporting deliverables:

---

### Component 1 — Python Scanner (`iamwatching/scanners/`)

Build three async scanners using `asyncio` and `asyncio.gather` for bulk concurrency. Each scanner must:

**AWS (`aws_scanner.py`)**
- Use `aioboto3` (async boto3) throughout. No sync boto3 calls.
- Extract: IAM users (with attached + inline policies, password last used), IAM roles (with trust policies parsed for `sts:AssumeRole` chains), IAM groups, customer-managed policies (with default version document fetched).
- Extract resource-based policies from: S3 buckets, Lambda functions (function policy JSON).
- Extract **compute metadata specifically to find cross-cloud keys**:
  - Lambda: `Environment.Variables` dict — scan with regex
  - EC2: `DescribeInstanceAttribute(Attribute='userData')` → base64-decode → scan
  - ECS Task Definitions: all container `environment` arrays → scan
- Cross-cloud detection regex patterns (compile once at module level):
  - `aws_access_key`: `(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])`
  - `gcp_api_key`: `AIza[0-9A-Za-z\-_]{35}`
  - `gcp_service_account`: `"type"\s*:\s*"service_account"`
  - `azure_client_secret`: case-insensitive match on `AZURE_CLIENT_SECRET=<value>`
  - `azure_tenant_id`: case-insensitive UUID pattern
- Return `AWSScanResult` dataclass with: `account_id`, `region`, `principals` (list of `AWSPrincipal`), `resources` (list of `AWSResource`), `managed_policies`, `discovered_credentials`, `errors`.
- Truncate raw credential values to 120 chars before storing.

**Azure (`azure_scanner.py`)**
- Use `azure.identity.aio.DefaultAzureCredential` for async auth.
- Use `msgraph` SDK for AAD users and service principals.
- Use `azure.mgmt.authorization.aio.AuthorizationManagementClient` for role assignments and role definitions.
- Extract compute metadata:
  - Function Apps: `WebSiteManagementClient.web_apps.list_application_settings()` → scan env vars
  - VMs: `os_profile.custom_data` + iterate extensions for `CustomScript`/`CustomScriptExtension` → scan
- Return `AzureScanResult` with subscription_id, tenant_id, principals, resources, role_definitions, discovered_credentials.

**GCP (`gcp_scanner.py`)**
- Use `google.auth.default()` for credential loading.
- Use `googleapiclient.discovery.build("iam", "v1")` and `build("cloudresourcemanager", "v1")` via `loop.run_in_executor` (sync SDK wrapped).
- Use async clients for: `functions_v1.CloudFunctionsServiceAsyncClient`, `run_v2.ServicesAsyncClient`, `compute_v1.InstancesClient` (sync, wrapped).
- Extract:
  - Service accounts with keys (list via IAM API) and their own IAM policies
  - Project-level IAM policy bindings (all `roles/*` for all members)
  - Cloud Functions: `environment_variables` dict
  - Cloud Run: container `env` arrays
  - GCE: `metadata.items` for keys `startup-script`, `user-data`, `startup-script-url`
- Attach project-level IAM bindings back to service account objects.
- Return `GCPScanResult` with project_id, principals, resources, project_iam_policy, discovered_credentials.

---

### Component 2 — Handshake Module (`iamwatching/handshake/verifier.py`)

Implement non-destructive credential verification with a `CredentialVerifier` class and three cloud-specific verifier functions. All calls must be strictly read-only identity checks. No resource enumeration with discovered credentials.

- **AWS**: Call `sts:GetCallerIdentity` using `aioboto3.Session` with the supplied `aws_access_key_id` + `aws_secret_access_key` (+ optional session token). Parse the response for `Arn` and `Account`. Map `ClientError` codes: `InvalidClientTokenId`/`AuthFailure` → `INVALID`, `Throttling` → `RATE_LIMITED`.
- **Azure**: POST to `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token` with `grant_type=client_credentials`. On success, base64-decode the JWT payload (no signature validation needed) to extract `appid`, `tid`, `oid`. Set `verified_link=True`.
- **GCP**: Load `google.oauth2.service_account.Credentials` from key JSON dict, refresh in executor, then GET `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}`. Parse `email` and `project_id` from the key JSON.

`VerificationStatus` enum: `VALID`, `INVALID`, `RATE_LIMITED`, `NETWORK_ERROR`, `INSUFFICIENT_DATA`, `SKIPPED`.

`VerificationResult` dataclass: `credential_source_cloud`, `credential_source_resource`, `credential_type`, `target_cloud`, `status`, `identity`, `account`, `raw_response`, `error`, `verified_link` (bool).

`CredentialVerifier.verify_all(creds, context_map)` — dispatches concurrently via `asyncio.Semaphore(concurrency=5)`.

---

### Component 3 — Graph Importer (`iamwatching/graph/importer.py`)

Use the **async** Neo4j driver (`neo4j.AsyncGraphDatabase`). Apply idempotent `MERGE` for all node and edge operations. Apply uniqueness constraints on startup.

**Node labels and key properties:**
- `AWSPrincipal` → `arn`
- `AzurePrincipal` → `object_id`
- `GCPPrincipal` → `email`
- `AWSResource` → `arn`
- `AzureResource` → `resource_id`
- `GCPResource` → `resource_id`
- `RoleDefinition` → `role_id`
- `SAKey` → `key_id`
- `StateChangeEvent` → `timestamp`

**Edge types:**
- `HAS_PERMISSION {action, effect, condition}` — Principal → Resource
- `CAN_ASSUME {condition}` — AWSPrincipal → AWSPrincipal (from trust policy `Statement[].Principal.AWS`)
- `ASSIGNED_ROLE {scope, condition}` — AzurePrincipal → RoleDefinition
- `HAS_BINDING {role}` — GCPPrincipal → GCPResource
- `CROSS_CLOUD_LINK {cred_type, verified, status, target_cloud, source_cloud, account}` — Resource → Principal
- `HAS_KEY` — GCPPrincipal → SAKey

`GraphImporter.import_all(aws_result, azure_result, gcp_result, verification_results)` orchestrates all imports and returns a stats dict per cloud.

---

### Component 4 — Pattern Matcher (`iamwatching/patterns/matcher.py`)

14 Cypher detection rules across 4 namespaces. Each rule is a tuple: `(rule_id, title, Severity, description, cypher_query, recommendation, mitre_attack_list)`.

**AWS rules (prefix AWS-):**
- `AWS-001` CRITICAL: Shadow Admin via `iam:PassRole` — match principals with PassRole permission who can reach admin roles via `CAN_ASSUME`
- `AWS-002` CRITICAL: Shadow Admin via `iam:CreatePolicyVersion` — principals with policy version write access
- `AWS-003` HIGH: Wildcard `*` resource on sensitive IAM/STS actions
- `AWS-004` HIGH: Cross-account role trust without `ExternalId` condition — `src.account_id <> tgt.account_id AND NOT e.condition CONTAINS 'ExternalId'`
- `AWS-005` CRITICAL: Verified cross-cloud credential in AWS compute — `CROSS_CLOUD_LINK {verified: true}`
- `AWS-006` HIGH: Lambda executing with admin-equivalent role
- `AWS-007` MEDIUM: IAM user without MFA

**Azure rules (prefix AZ-):**
- `AZ-001` CRITICAL: Role Assignment Write (shadow Owner) — principals with Owner or UserAccessAdministrator
- `AZ-002` HIGH: Azure SP secret exposed in Function App settings
- `AZ-003` HIGH: External/guest SP with Contributor or higher at subscription scope

**GCP rules (prefix GCP-):**
- `GCP-001` CRITICAL: SA impersonation chain — `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser`
- `GCP-002` HIGH: Primitive role (`roles/owner`, `roles/editor`) at project level
- `GCP-003` CRITICAL: Cross-cloud credential in Cloud Function env vars

**Cross-cloud (prefix XC-):**
- `XC-001` CRITICAL: Confirmed cross-cloud lateral movement — `CROSS_CLOUD_LINK {verified: true}` across any node type

`PatternMatcher.run_all(severity_filter)` runs all rules, returns findings sorted CRITICAL → LOW, filtering those with `len(affected_nodes) > 0` only.

---

### Component 5 — Go Daemon (`daemon/main.go`)

A single-file Go program (~560 lines) using:
- `github.com/aws/aws-sdk-go-v2` for IAM polling
- `github.com/neo4j/neo4j-go-driver/v5` for graph writes
- `github.com/spf13/cobra` for CLI

**Architecture:**
```
main() → Scheduler.Run() → AWSPoller.Poll() → StateDiffer → Neo4jWriter.WriteDiff()
```

**IAMSnapshot**: contains `AccountID`, `Region`, `Timestamp`, and three `map[string]string` (ARN → SHA-256[:8] content hash) for Roles, Users, Policies. `computeFingerprint()` hashes the combined map for fast equality check.

**StateDiff**: `AddedRoles`, `RemovedRoles`, `ModifiedRoles` (same for Users, Policies). `HasChanges()` returns bool.

**diffSnapshots(prev, curr)**: O(n) map comparison — iterate curr to find adds/modifies, iterate prev to find removals.

**Neo4jWriter.WriteDiff()**: Single managed transaction. Marks removed principals as `deleted=true`. Creates `StateChangeEvent` node with all delta arrays as properties. Skip write if `!diff.HasChanges()`.

**Scheduler**: Runs `tick()` immediately on startup, then on every `PollIntervalSeconds` tick. Graceful shutdown on `SIGTERM`/`SIGINT` via `context.WithCancel`.

Cobra flags: `--poll-interval`, `--aws-regions`, `--aws-profile`, `--neo4j`, `--neo4j-user`, `--neo4j-password`, `--workers`, `--dry-run`, `--log-level`.

Use `log/slog` with `JSONHandler` for structured output.

---

### Component 6 — Deployment (`pyproject.toml` + Docker)

**`pyproject.toml`**:
- `name = "iamwatching"`, `version = "1.2.0"`, `requires-python = ">=3.11"`
- Entry point: `iamwatching = "iamwatching.cli.main:main"`
- Dependencies: `aioboto3>=13.0`, `botocore>=1.34`, `azure-identity>=1.17`, `azure-mgmt-authorization>=4.0`, `azure-mgmt-compute>=32.0`, `azure-mgmt-resource>=23.0`, `azure-mgmt-web>=7.3`, `msgraph-sdk>=1.5`, `google-auth>=2.30`, `google-cloud-functions>=1.16`, `google-cloud-run>=0.10`, `google-cloud-compute>=1.17`, `google-api-python-client>=2.130`, `neo4j>=5.20`, `aiohttp>=3.9`, `click>=8.1`, `rich>=13.7`
- Dev extras: `pytest>=8.0`, `pytest-asyncio>=0.23`, `pytest-mock>=3.14`, `moto[iam,s3,lambda,ec2,sts]>=5.0`, `pyinstaller>=6.8`, `black`, `ruff`, `mypy`

**`docker/docker-compose.yml`**: Three services:
1. `neo4j`: `neo4j:5.20-community`, ports 7474+7687, APOC+GDS plugins, health check on `http://localhost:7474`
2. `daemon`: Go binary, profile-gated (`--profile daemon`), depends on neo4j health
3. `auditor`: Python image, profile-gated (`--profile audit`)

**`docker/Dockerfile.auditor`**: `FROM python:3.12-slim`, `COPY . .`, `RUN pip install -e ".[all]"`, `ENTRYPOINT ["iamwatching"]`

**`docker/Dockerfile.daemon`**: Multi-stage — `FROM golang:1.22-alpine AS builder`, build with `-ldflags="-s -w"`, `FROM alpine:3.19`, copy binary.

---

### Supporting Deliverable A — Structured Logging Module (`iamwatching/logging_module/`)

A dedicated logging subsystem that ALL other modules import from. Two files:

**`logger.py`**:
- `EventType` str enum with values: `SCAN_START`, `SCAN_END`, `CRED_FOUND`, `CRED_VERIFIED`, `GRAPH_WRITE`, `PATTERN_RUN`, `FINDING`, `DEPLOY_STEP`, `DEPLOY_COMPLETE`, `DEPLOY_ERROR`, `DAEMON_POLL`, `DAEMON_DIFF`, `AUTH_ERROR`, `NETWORK_ERROR`, `ERROR`, `INFO`, `DEBUG`
- `redact(text)` function — applies compiled regex patterns to strip: AWS secret keys, AWS session tokens, Azure client secrets, Bearer tokens, GCP `private_key` JSON fields, generic `password=` patterns
- `JSONFormatter(logging.Formatter)` — emits single-line JSON per record with fields: `ts`, `ms`, `level`, `logger`, `event`, `message`, `correlation_id`, `phase`, `cloud`, `duration_ms`, and any extra fields. Calls `redact()` on message.
- `IamLogger` class — wraps `logging.getLogger()`, adds typed methods:
  - `scan_start(cloud, **kwargs)`, `scan_end(cloud, principals, resources, creds_found, duration_ms)`
  - `cred_found(cred_type, source_resource, target_cloud, source_cloud)` at WARNING level
  - `cred_verified(...)` at CRITICAL if `verified=True`, INFO otherwise
  - `graph_write(operation, node_label, count, duration_ms)` at DEBUG
  - `pattern_run(rule_id, title)`, `finding(rule_id, severity, title, affected_count)`
  - `deploy_step(step, detail)`, `deploy_complete(step, duration_ms)`, `deploy_error(step, error)`
  - `daemon_poll(account, fingerprint, roles, users, policies)`, `daemon_diff(account, added, removed, modified)`
  - `timed_phase(phase_name, cloud)` async context manager — logs start/end with elapsed ms, logs ERROR on exception
  - `child(suffix, **overrides)` — returns child logger inheriting `correlation_id`
- `configure_logging(level, log_dir, json_file, audit_file, console_json, correlation_id)`:
  - Console: `RichHandler` (human-readable) OR JSON `StreamHandler` based on `console_json`
  - File (if `json_file=True`): `RotatingFileHandler` at `logs/iamwatching.jsonl`, 10 MB / 5 backups
  - Audit file (if `audit_file=True`): `RotatingFileHandler` at `logs/audit.jsonl`, WARNING+, 10 MB / 10 backups
  - Guard against double-configuration with `_CONFIGURED` global
  - Returns `run_id` (auto-generated 8-char hex UUID if not supplied)
- `get_logger(module, correlation_id, phase, cloud)` — factory function
- `new_correlation_id()` — returns `str(uuid.uuid4())[:8]`

**`__init__.py`**: exports all public symbols.

---

### Supporting Deliverable B — Deployment Script (`deploy.sh`)

A bash script (~1,000 lines) with `set -euo pipefail` that runs 9 numbered steps with full structured logging. The script **self-generates** `start.sh`, `stop.sh`, and `uninstall.sh` into the project root on first run.

**Critical implementation requirement — portable millisecond timer:**
Do NOT use `date +%s%3N` — this is GNU-only and breaks on macOS (BSD date). Use Python instead:
```bash
_now_ms() {
    python3 -c "import time; print(int(time.time() * 1000))"
}
_elapsed() {
    local start="$1"
    local end; end=$(_now_ms)
    echo $(( end - start ))
}
```

**Flags:**
- `--native` — Enable PyInstaller native build (opt-in, slow; NOT the default)
- `--skip-tests`, `--skip-docker`, `--skip-daemon`, `--skip-native`
- `--dev` — Install dev extras
- `--log-level DEBUG|INFO|WARN` (default: INFO)
- `--log-dir DIR` (default: ./logs)
- `--neo4j-password PW`
- `--help`

**`--native` flag logic:** Native build is OFF by default (it takes 1-3 minutes). `--native` sets `BUILD_NATIVE=1` and `SKIP_NATIVE=0`. `--skip-native` sets `SKIP_NATIVE=1`. If neither flag is given, `SKIP_NATIVE` defaults to 1. This prevents unintentional slow builds.

**Steps:**
1. Prerequisite checks: `python3` (must be 3.11+, using integer comparison not string), `pip3`, `docker` (check both `command -v` AND `docker info`), `go`
2. Python venv at `.venv/`, activate, upgrade pip, `pip install -e ".[dev]"` if tests or native enabled
3. `pytest tests/ -v --tb=short` — fatal on failure unless `--skip-tests`
4. Go daemon: `go mod download` then `go build -ldflags="-s -w -X main.Version=1.2.0 -X main.BuildTime=..."` to `dist/iamwatching-daemon`. Cross-compile Linux amd64 if on macOS.
5. PyInstaller: only if `--native` flag given. Install if absent. Run spec. Non-fatal on failure.
6. Docker image builds (skip if Docker not running)
7. `docker compose up -d neo4j` + poll `http://localhost:7474` for 90s (45 iterations × 2s)
8. Apply Neo4j constraints via inline Python heredoc with `AsyncGraphDatabase`
9. **Generate** `start.sh`, `stop.sh`, `uninstall.sh` via heredocs. Print summary with all endpoints, deliverable paths, and management commands.

**Logging in the script:**
- `_write_log level event message [detail]` — appends JSON to `$LOG_FILE`, escaping double-quotes with single-quotes before writing
- `run_cmd "label" <command>` — redirects command stdout+stderr to jsonl, logs elapsed ms, writes to audit file
- Two log files: `logs/deploy-YYYYMMDD-HHMMSS.jsonl` (everything) and `logs/deploy-audit-YYYYMMDD-HHMMSS.jsonl` (WARN/ERROR only)

---

### Supporting Deliverable B2 — `start.sh` (auto-generated by deploy.sh)

Starts Neo4j and optionally the Go daemon.

**Flags:** `--daemon`, `--poll-interval SECONDS`

**Logic:**
1. Verify Docker is running; exit with clear error if not
2. `docker compose up -d neo4j`
3. Poll `http://localhost:7474` for 90s
4. Activate `.venv/bin/activate`
5. If `--daemon`: check `dist/iamwatching-daemon` exists, check for stale `.daemon.pid`, launch with `nohup ... &`, write PID to `.daemon.pid`, verify process alive after 1s

---

### Supporting Deliverable B3 — `stop.sh` (auto-generated by deploy.sh)

Gracefully stops all services.

**Flags:** `--neo4j-only`, `--daemon-only`

**Logic:**
1. If `.daemon.pid` exists: send `SIGTERM`, wait up to 10s in loop, send `SIGKILL` if still alive, remove `.daemon.pid`
2. `docker compose stop neo4j` (preserves data volume)

---

### Supporting Deliverable B4 — `uninstall.sh` (auto-generated by deploy.sh)

Removes all IamWatching artifacts. Prompts before destructive operations unless `--yes`.

**Flags:** `--yes` / `-y`, `--keep-data` (preserve Neo4j Docker volume), `--keep-logs`

**Logic (in order):**
1. Stop daemon (SIGTERM → SIGKILL) and Neo4j container
2. `docker compose down -v` + explicit `docker volume rm` for named volumes (unless `--keep-data`)
3. `docker rmi iamwatching-auditor:latest iamwatching-daemon:latest`
4. `rm -rf .venv/`
5. `rm -rf dist/ build/`
6. `find . -name __pycache__ -exec rm -rf {} +` and `find . -name "*.pyc" -delete`
7. `rm -rf logs/` (unless `--keep-logs`)

---

### Supporting Deliverable C

### Supporting Deliverable C — Native Executable (`iamwatching.spec`)

A PyInstaller spec file that produces `dist/iamwatching` — a self-contained binary with no Python dependency.

- `Analysis` entry point: `iamwatching/cli/main.py`
- `hiddenimports` list covering: all `iamwatching.*` submodules, `aioboto3`, `aiobotocore`, `botocore`, `azure.*`, `msal`, `google.auth`, `google.oauth2`, `google.cloud.*`, `neo4j`, `aiohttp`, `click`, `rich`, `cryptography`, `OpenSSL`, `certifi`
- `datas`: include `README.md`, `docs/`, and `botocore/data` (service endpoint JSON files — critical for AWS SDK)
- `excludes`: `tkinter`, `matplotlib`, `scipy`, `numpy`, `pandas`, `PIL`, `IPython`, `pytest`, `black`, `ruff`, `mypy`, `moto`, `sphinx`
- `EXE`: `strip=True`, `upx=True`, `console=True`, `onefile=True`
- Detailed inline comments explaining each section

---

### CLI Commands

`iamwatching audit` — full pipeline with options:
- `--aws/--no-aws`, `--azure/--no-azure`, `--gcp/--no-gcp`
- `--aws-profile`, `--aws-regions` (comma-separated)
- `--azure-subscription` (env: `AZURE_SUBSCRIPTION_ID`), `--azure-tenant`
- `--gcp-project` (env: `GCP_PROJECT_ID`), `--gcp-locations`
- `--verify/--no-verify`, `--import-graph/--no-import-graph`, `--detect/--no-detect`
- `--severity CRITICAL|HIGH|MEDIUM|LOW|INFO`
- `--output FILE` (JSON report)
- `--verbose/-v`, `--log-dir DIR`, `--json-logs/--no-json-logs`

`iamwatching detect` — pattern detection only against existing graph

`iamwatching query "CYPHER"` — run custom Cypher query

---

### Documentation

- `docs/scanner-policy.json` — minimal AWS IAM policy for the scanner identity (ListUsers, ListRoles, ListPolicies, GetPolicyVersion, GetCallerIdentity, DescribeInstances, ListFunctions, GetPolicy, DescribeTaskDefinition, ListTaskDefinitions, DescribeInstanceAttribute, ListBuckets, GetBucketPolicy)
- `docs/sample-cypher-queries.cypher` — 10 ready-to-run queries: cross-cloud links, assume-role chains, Lambda credential leaks, Azure Owner SPs, GCP impersonation, daemon delta events, resources with env vars, orphaned principals, full graph overview

---

### Tests (`tests/`)

Three test files:

**`test_aws_scanner.py`**: `moto` (`@mock_aws`) integration tests — create users/roles/policies via boto3, run scanner, assert results. Unit tests for all 5 regex patterns (valid + invalid + truncation at 120 chars).

**`test_handshake.py`**: Mock `aioboto3` and `aiohttp`. Test valid key → VALID, invalid ClientError → INVALID, missing secret → INSUFFICIENT_DATA, unknown cred_type → SKIPPED, `verify_all` aggregation.

**`test_pattern_matcher.py`**: Assert all 14 rules have rule_id, title, Severity enum, non-empty cypher, recommendation, mitre list. Assert ≥4 CRITICAL rules. Assert AWS/AZ/GCP/XC namespaces all present. Mock Neo4j driver and verify `run_all` filter behavior.

---

### Final File Layout

```
iamwatching/
├── deploy.sh                            ← Deployment script (chmod +x)
├── start.sh                             ← Start services (auto-generated by deploy.sh)
├── stop.sh                              ← Stop services (auto-generated by deploy.sh)
├── uninstall.sh                         ← Remove all artifacts (auto-generated by deploy.sh)
├── iamwatching.spec                     ← PyInstaller native build spec
├── pyproject.toml                       ← PEP 517 package + CLI entry point
├── README.md                            ← Full usage, schema, detection table
├── docker-compose.yml                   ← Symlink to docker/docker-compose.yml
├── iamwatching/
│   ├── __init__.py
│   ├── cli/main.py                      ← Click CLI: audit|detect|query
│   ├── scanners/
│   │   ├── aws_scanner.py               ← Async IAM + Lambda/EC2/ECS scan
│   │   ├── azure_scanner.py             ← Async AAD + Functions/VMs scan
│   │   └── gcp_scanner.py              ← Async SA + Functions/Run/GCE scan
│   ├── handshake/verifier.py            ← WhoAmI verification (3 clouds)
│   ├── graph/importer.py                ← Neo4j async importer
│   ├── patterns/matcher.py              ← 14-rule Cypher detection engine
│   └── logging_module/
│       ├── __init__.py
│       └── logger.py                    ← Structured logging + redaction
├── daemon/
│   ├── main.go                          ← Go continuous poller + state differ
│   └── go.mod
├── docker/
│   ├── docker-compose.yml
│   ├── Dockerfile.auditor
│   └── Dockerfile.daemon
├── docs/
│   ├── scanner-policy.json
│   └── sample-cypher-queries.cypher
└── tests/
    ├── test_aws_scanner.py
    ├── test_handshake.py
    └── test_pattern_matcher.py
```

Replace `"Aniza Corp"` with your organization name throughout.

---

## Changelog

### v1.2.0
- **Fix**: `--native` flag was missing from argument parser — now correctly recognised
- **Fix**: `date +%s%3N` millisecond timer replaced with portable Python-based `_now_ms()` (macOS BSD `date` does not support `%3N`)
- **New**: `deploy.sh` now generates three management scripts at step 9:
  - `start.sh` — starts Neo4j, activates venv, optionally starts Go daemon
  - `stop.sh` — SIGTERM (10s grace) + SIGKILL to daemon, stops Neo4j container
  - `uninstall.sh` — tears down everything with interactive confirmation

### Deployment Script Flags (v1.2.0)
| Flag | Effect |
|---|---|
| `--native` | Enable PyInstaller native build (opt-in, ~2 min) |
| `--skip-tests` | Skip pytest suite |
| `--skip-docker` | Skip all Docker steps |
| `--skip-daemon` | Skip Go daemon build |
| `--dev` | Install dev extras (pytest, ruff, mypy, pyinstaller) |
| `--log-level DEBUG\|INFO\|WARN` | Verbosity |
| `--log-dir PATH` | Log file directory (default: `./logs`) |
| `--neo4j-password PW` | Neo4j password (default: `iamwatching`) |

### v1.3.0 — pip install fixes
- **Fix**: `build-backend = "setuptools.backends.legacy:build"` → `"setuptools.build_meta"` (the `backends.legacy` submodule doesn't exist in setuptools < 69.1 and errors on many systems)
- **Fix**: `aiobotocore` added as explicit dependency (required by `aioboto3` but wasn't pinned)
- **Fix**: `google-cloud-run>=0.10` → `>=0.10.9` (minimum that supports Python 3.13+)
- **Fix**: `msgraph-sdk>=1.5` → `>=1.0` (v1.5 doesn't exist; current latest is ~1.3.x)
- **Fix**: Added `google-auth-httplib2>=0.2` (implicit dep of `google-api-python-client` that was missing)
- **Improvement**: `deploy.sh` now streams the last 40 lines of `pip` output to stderr on install failure, so the real error is immediately visible without needing to open the log file
- **Improvement**: Pre-flight `pip install --dry-run setuptools wheel` check before full install

### pyproject.toml — correct values (v1.3.0)
```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"   # NOT setuptools.backends.legacy:build

[project]
dependencies = [
    "aioboto3>=13.1",
    "aiobotocore>=2.13",      # explicit — required by aioboto3
    "botocore>=1.34",
    "azure-identity>=1.17",
    "azure-mgmt-authorization>=4.0",
    "azure-mgmt-compute>=32.0",
    "azure-mgmt-resource>=23.0",
    "azure-mgmt-web>=7.3",
    "msgraph-sdk>=1.0",       # NOT >=1.5 (doesn't exist)
    "google-auth>=2.30",
    "google-auth-httplib2>=0.2",  # explicit — required by google-api-python-client
    "google-cloud-functions>=1.16",
    "google-cloud-run>=0.10.9",   # NOT >=0.10 (too old)
    "google-cloud-secret-manager>=2.20",
    "google-api-python-client>=2.130",
    "google-cloud-compute>=1.17",
    "neo4j>=5.20",
    "aiohttp>=3.9",
    "click>=8.1",
    "rich>=13.7",
]
```
