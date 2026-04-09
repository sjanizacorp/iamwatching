# IamWatching

**Multi-Cloud IAM Security Auditor** — discover shadow admins, cross-cloud credential leaks, and privilege escalation paths across AWS, Azure, and GCP. Built by Aniza Corp Security Research.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        iamwatching audit                         │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │ AWSScanner  │ │AzureScanner │ │ GCPScanner  │   Phase 1: Scan
   │  (asyncio)  │ │  (asyncio)  │ │  (asyncio)  │
   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
          └───────────────┼───────────────┘
                          ▼
                 ┌─────────────────┐
                 │CredentialVerif- │   Phase 2: Handshake
                 │    ier          │   (WhoAmI calls)
                 │ (non-destructive│
                 │  WhoAmI calls)  │
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │  GraphImporter  │   Phase 3: Graph Load
                 │    (Neo4j)      │
                 │  Nodes + Edges  │
                 └────────┬────────┘
                          ▼
                 ┌─────────────────┐
                 │ PatternMatcher  │   Phase 4: Detect
                 │ (Cypher rules)  │
                 │  11 rule engine │
                 └────────┬────────┘
                          ▼
                   Rich CLI Report
                   + JSON output

  ┌──────────────────────────────────┐
  │  Go Daemon (continuous polling)  │   Background: State Diff
  │  Polls IAM → SHA256 fingerprint  │
  │  → diff → writes only deltas     │
  └──────────────────────────────────┘
```

---

## Quickstart

### 1. Start Neo4j

```bash
cd docker
docker compose up -d neo4j
# Neo4j Browser: http://localhost:7474  (neo4j / iamwatching)
```

### 2. Install IamWatching

```bash
pip install -e ".[all]"
# or from PyPI (once published):
pip install iamwatching
```

### 3. Run an Audit

```bash
# AWS only (uses default credential chain)
iamwatching audit --aws --aws-regions us-east-1,eu-west-1

# Multi-cloud
iamwatching audit \
  --aws \
  --azure --azure-subscription $AZURE_SUBSCRIPTION_ID --azure-tenant $AZURE_TENANT_ID \
  --gcp  --gcp-project $GCP_PROJECT_ID \
  --output report.json

# AWS only, skip graph import (offline analysis)
iamwatching audit --aws --no-import-graph --no-detect

# Run detection only against existing graph
iamwatching detect --severity CRITICAL

# Custom Cypher query
iamwatching query "MATCH (p:AWSPrincipal)-[:CAN_ASSUME]->(r) RETURN p.arn, r.arn LIMIT 20"
```

### 4. Docker one-shot audit

```bash
cd docker
AWS_PROFILE=your-profile docker compose --profile audit up
# Report written to docker/reports/audit-report.json
```

### 5. Continuous Daemon

```bash
# Build and run the Go daemon
cd daemon
go build -o iamwatching-daemon .
./iamwatching-daemon --poll-interval 300 --neo4j bolt://localhost:7687

# Or via Docker Compose
docker compose --profile daemon up
```

---

## Detection Rules

| ID      | Severity | Title                                                        | MITRE                         |
|---------|----------|--------------------------------------------------------------|-------------------------------|
| AWS-001 | CRITICAL | Shadow Admin via iam:PassRole                                | T1078.004, T1098.001          |
| AWS-002 | CRITICAL | Shadow Admin via iam:CreatePolicyVersion                     | T1078.004, T1484              |
| AWS-003 | HIGH     | Wildcard (*) Resource on Sensitive IAM Actions               | T1078.004                     |
| AWS-004 | HIGH     | Cross-Account Role Trust Without External ID Condition       | T1199, T1078.004              |
| AWS-005 | CRITICAL | Verified Cross-Cloud Credential in AWS Compute               | T1552.001, T1552.005          |
| AWS-006 | HIGH     | Lambda Function Executing with Admin-Equivalent Role         | T1078.004, T1610              |
| AWS-007 | MEDIUM   | IAM User Without MFA Enabled                                 | T1078.004                     |
| AZ-001  | CRITICAL | Shadow Admin via Azure Role Assignment Write                  | T1078.004, T1484              |
| AZ-002  | HIGH     | Azure SP Secret Exposed in Function App Settings             | T1552.001                     |
| AZ-003  | HIGH     | External SP with Contributor or Higher                       | T1199                         |
| GCP-001 | CRITICAL | GCP Service Account Impersonation Chain                      | T1134.001, T1548              |
| GCP-002 | HIGH     | Primitive Role (Owner/Editor) at Project Level               | T1078.004                     |
| GCP-003 | CRITICAL | Cross-Cloud Credential in GCP Cloud Function                 | T1552.001, T1552.005          |
| XC-001  | CRITICAL | Confirmed Cross-Cloud Lateral Movement Path                  | T1078.004, T1199, T1552.001   |

---

## Neo4j Graph Schema

### Node Labels

| Label             | Key Property  | Description                              |
|-------------------|---------------|------------------------------------------|
| `AWSPrincipal`    | `arn`         | IAM Users, Roles, Groups                 |
| `AzurePrincipal`  | `object_id`   | AAD Users, Service Principals            |
| `GCPPrincipal`    | `email`       | Service Accounts, Users, Groups          |
| `AWSResource`     | `arn`         | S3, Lambda, EC2, ECS                     |
| `AzureResource`   | `resource_id` | Function Apps, VMs                       |
| `GCPResource`     | `resource_id` | Cloud Functions, Cloud Run, GCE          |
| `RoleDefinition`  | `role_id`     | Azure role definitions                   |
| `SAKey`           | `key_id`      | GCP Service Account keys                 |
| `StateChangeEvent`| compound      | Written by Go daemon on IAM delta        |

### Edge Types

| Type               | From         | To           | Properties                              |
|--------------------|--------------|--------------|----------------------------------------|
| `HAS_PERMISSION`   | Principal    | Resource     | `action`, `effect`, `condition`        |
| `CAN_ASSUME`       | AWSPrincipal | AWSPrincipal | `condition` (trust policy)             |
| `ASSIGNED_ROLE`    | AzurePrincipal | RoleDefinition | `scope`, `condition`              |
| `HAS_BINDING`      | GCPPrincipal | GCPResource  | `role`                                 |
| `CROSS_CLOUD_LINK` | Resource     | Principal    | `cred_type`, `verified`, `status`      |
| `HAS_KEY`          | GCPPrincipal | SAKey        | —                                      |

---

## Environment Variables

| Variable               | Default                  | Description                    |
|------------------------|--------------------------|--------------------------------|
| `NEO4J_URI`            | `bolt://localhost:7687`  | Neo4j connection URI           |
| `NEO4J_USERNAME`       | `neo4j`                  | Neo4j username                 |
| `NEO4J_PASSWORD`       | `iamwatching`            | Neo4j password                 |
| `NEO4J_DATABASE`       | `neo4j`                  | Neo4j database name            |
| `AWS_PROFILE`          | `default`                | AWS CLI profile                |
| `AZURE_SUBSCRIPTION_ID`| —                        | Azure subscription UUID        |
| `AZURE_TENANT_ID`      | —                        | Azure tenant UUID              |
| `GCP_PROJECT_ID`       | —                        | GCP project ID                 |

---

## Project Layout

```
iamwatching/
├── iamwatching/
│   ├── __init__.py
│   ├── scanners/
│   │   ├── aws_scanner.py       # Async IAM + compute metadata (Lambda/EC2/ECS)
│   │   ├── azure_scanner.py     # Async AAD + Function Apps + VMs
│   │   └── gcp_scanner.py       # Async SA + Cloud Functions + Cloud Run + GCE
│   ├── handshake/
│   │   └── verifier.py          # Non-destructive WhoAmI credential verification
│   ├── graph/
│   │   └── importer.py          # Neo4j graph loader (principals + resources + edges)
│   ├── patterns/
│   │   └── matcher.py           # Cypher-based shadow admin + escalation detection
│   └── cli/
│       └── main.py              # Click CLI: audit | detect | query
├── daemon/
│   ├── main.go                  # Go continuous poller + state differ + Neo4j writer
│   └── go.mod
├── docker/
│   ├── docker-compose.yml       # Neo4j + Daemon + Auditor services
│   ├── Dockerfile.auditor       # Python scanner image
│   └── Dockerfile.daemon        # Go daemon image (multi-stage)
├── tests/
│   ├── test_aws_scanner.py      # moto-based IAM scan tests
│   ├── test_handshake.py        # Mock cloud API verification tests
│   └── test_pattern_matcher.py  # Cypher rule validation tests
└── pyproject.toml               # PEP 517 installable package + CLI entry point
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Security Notes

- **Read-only**: All cloud API calls are strictly read-only. The scanner uses `List*`, `Get*`, `Describe*` operations only.
- **Credential verification**: WhoAmI calls (`sts:GetCallerIdentity`, Azure token introspection, GCP tokeninfo) are the most conservative identity checks available. No resource enumeration is performed with discovered credentials.
- **Secrets handling**: Discovered raw credential values are truncated to 120 chars and stored only in Neo4j (your controlled backend). They are never logged.
- **Least-privilege scanner role**: Recommended IAM policy for the scanner identity is in `docs/scanner-policy.json`.
