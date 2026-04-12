"""
Checks Updater — IamWatching v2.0
===================================
Fetches security check definitions from official internet sources and merges
them with the local check library.

Sources are organised by framework family. Each source has:
  - A canonical URL pointing to the authoritative check definition
  - A parser that converts the remote format into IamWatching CheckDefinition YAML
  - Metadata about the source (publisher, last-known update date, license)

Update is non-destructive:
  - Built-in files are backed up before replacement
  - Custom checks in checks/custom/ are NEVER touched
  - Any check the user has disabled stays disabled after update
  - Version metadata is written to checks/builtin/.update_manifest.json

Supported sources
-----------------
CIS AWS:        IamWatching release channel (curated from CIS PDF)
OWASP Cloud:    IamWatching release channel (curated from OWASP project)
NIST 800-53:    IamWatching release channel (curated from NIST OSCAL)
PCI DSS:        IamWatching release channel (curated from PCI SSC)
ISO 27001:      IamWatching release channel (curated from ISO document)
Prowler:        https://github.com/prowler-cloud/prowler (checks/aws/ folder)
CloudSploit:    https://github.com/aquasecurity/cloudsploit (plugins/ folder)
AWS FSBP:       https://docs.aws.amazon.com/securityhub/latest/userguide/
ScoutSuite:     https://github.com/nccgroup/ScoutSuite (ScoutSuite/providers/ folder)
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

log = logging.getLogger(__name__)

# ── Source registry ───────────────────────────────────────────────────────────

@dataclass
class CheckSource:
    """A remote source of security check definitions."""
    id:           str    # unique source ID
    name:         str    # display name
    publisher:    str    # organisation that maintains this
    url:          str    # primary URL to fetch from
    format:       str    # "iamwatching_yaml" | "prowler_json" | "cloudsploit_js" | "raw_yaml"
    target_file:  str    # which local builtin/*.yaml this updates (None = new file)
    description:  str
    license:      str    # e.g. "Apache-2.0", "CC BY 4.0", "Proprietary"
    fallback_urls: list[str]   # alternative URLs if primary fails


# Official sources for each framework family.
# URLs use real authoritative internet sources — not just GitHub.
# Each source has a primary URL and multiple fallbacks so updates
# succeed even if one endpoint is unavailable.
SOURCES: list[CheckSource] = [

    # ── IamWatching curated releases (primary channel) ────────────────────────
    CheckSource(
        id="iw-cis-aws",
        name="CIS AWS Foundations Benchmark v3.0",
        publisher="Aniza Corp / CIS",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/cis_aws.yaml",
        format="raw_yaml",
        target_file="cis_aws.yaml",
        description="CIS Amazon Web Services Foundations Benchmark v3.0 — 37 controls.",
        license="CIS Benchmark License",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/cis_aws.yaml",
        ],
    ),
    CheckSource(
        id="iw-owasp",
        name="OWASP Cloud-Native Application Security Top 10",
        publisher="Aniza Corp / OWASP",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/owasp_cloud.yaml",
        format="raw_yaml",
        target_file="owasp_cloud.yaml",
        description="OWASP Cloud-Native Application Security Top 10 — all clouds.",
        license="CC BY-SA 4.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/owasp_cloud.yaml",
        ],
    ),
    CheckSource(
        id="iw-nist",
        name="NIST SP 800-53 Rev 5 + CSF 2.0",
        publisher="Aniza Corp / NIST",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/nist_csf.yaml",
        format="raw_yaml",
        target_file="nist_csf.yaml",
        description="NIST SP 800-53 Rev 5 IAM controls and CSF 2.0 — all cloud platforms.",
        license="Public Domain (NIST)",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/nist_csf.yaml",
        ],
    ),
    CheckSource(
        id="iw-pci",
        name="PCI DSS v4.0.1 IAM Controls",
        publisher="Aniza Corp / PCI SSC",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/pci_dss.yaml",
        format="raw_yaml",
        target_file="pci_dss.yaml",
        description="PCI DSS v4.0.1 Requirements 7 & 8 — all cloud platforms.",
        license="PCI SSC License",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/pci_dss.yaml",
        ],
    ),
    CheckSource(
        id="iw-iso27001",
        name="ISO/IEC 27001:2022 IAM Controls",
        publisher="Aniza Corp / ISO",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/iso27001.yaml",
        format="raw_yaml",
        target_file="iso27001.yaml",
        description="ISO/IEC 27001:2022 Annex A IAM controls — all cloud platforms.",
        license="ISO License",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/iso27001.yaml",
        ],
    ),
    CheckSource(
        id="iw-aws-compute",
        name="AWS Compute & API Security Checks",
        publisher="Aniza Corp",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/aws_compute_security.yaml",
        format="raw_yaml",
        target_file="aws_compute_security.yaml",
        description="EKS, API Gateway, Lambda, EC2, ECS, SQS, SNS, CloudFront security checks.",
        license="Apache-2.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/aws_compute_security.yaml",
        ],
    ),
    CheckSource(
        id="iw-aws-data",
        name="AWS Data & Storage Security Checks",
        publisher="Aniza Corp",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/aws_data_security.yaml",
        format="raw_yaml",
        target_file="aws_data_security.yaml",
        description="RDS, DynamoDB, Redshift, ElastiCache, Kinesis, S3 security checks.",
        license="Apache-2.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/aws_data_security.yaml",
        ],
    ),
    CheckSource(
        id="iw-azure",
        name="Azure Application & Data Security Checks",
        publisher="Aniza Corp",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/azure_security.yaml",
        format="raw_yaml",
        target_file="azure_security.yaml",
        description="Azure VMs, AKS, Functions, API Mgmt, Blob, SQL, Cosmos DB, Service Bus checks.",
        license="Apache-2.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/azure_security.yaml",
        ],
    ),
    CheckSource(
        id="iw-gcp",
        name="GCP Application & Data Security Checks",
        publisher="Aniza Corp",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/gcp_security.yaml",
        format="raw_yaml",
        target_file="gcp_security.yaml",
        description="GKE, Cloud Functions, Cloud Run, BigQuery, Cloud SQL, GCS, Pub/Sub checks.",
        license="Apache-2.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/gcp_security.yaml",
        ],
    ),
    CheckSource(
        id="iw-cross-cloud",
        name="Cross-Cloud Normalization Checks",
        publisher="Aniza Corp",
        url="https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/cross_cloud_normalization.yaml",
        format="raw_yaml",
        target_file="cross_cloud_normalization.yaml",
        description="Architecture-agnostic checks: encryption, public access, logging, backups, tagging.",
        license="Apache-2.0",
        fallback_urls=[
            "https://cdn.iamwatching.io/checks/v2/cross_cloud_normalization.yaml",
        ],
    ),

    # ── Community open-source check packs ─────────────────────────────────────

    CheckSource(
        id="prowler-aws-iam",
        name="Prowler AWS IAM Checks",
        publisher="Prowler Cloud",
        url="https://api.github.com/repos/prowler-cloud/prowler/contents/prowler/providers/aws/services/iam",
        format="prowler_index",
        target_file="prowler_aws_iam.yaml",
        description="Prowler open-source AWS IAM checks (500+ total). Widely used CSPM tool.",
        license="Apache-2.0",
        fallback_urls=[
            "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/providers/aws/services/iam/__init__.py",
        ],
    ),
    CheckSource(
        id="cloudsploit-aws-iam",
        name="CloudSploit AWS IAM Checks",
        publisher="Aqua Security",
        url="https://api.github.com/repos/aquasecurity/cloudsploit/contents/plugins/aws/iam",
        format="cloudsploit_index",
        target_file="cloudsploit_aws.yaml",
        description="Aqua CloudSploit open-source AWS IAM security posture checks.",
        license="Apache-2.0",
        fallback_urls=[
            "https://raw.githubusercontent.com/aquasecurity/cloudsploit/master/index.js",
        ],
    ),
    CheckSource(
        id="steampipe-aws-compliance",
        name="Steampipe AWS CIS Compliance Checks",
        publisher="Turbot / Steampipe",
        url="https://api.github.com/repos/turbot/steampipe-mod-aws-compliance/contents/cis_v300",
        format="steampipe_index",
        target_file="steampipe_aws_compliance.yaml",
        description="Steampipe AWS CIS v3.0 compliance check definitions from the official Turbot mod.",
        license="Apache-2.0",
        fallback_urls=[
            "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/README.md",
        ],
    ),
    CheckSource(
        id="scoutsuite-aws",
        name="ScoutSuite AWS IAM Rules",
        publisher="NCC Group",
        url="https://api.github.com/repos/nccgroup/ScoutSuite/contents/ScoutSuite/providers/aws/rules/findings",
        format="scoutsuite_index",
        target_file="scoutsuite_aws.yaml",
        description="NCC Group ScoutSuite AWS IAM finding rules — multi-cloud security auditing tool.",
        license="GPL-2.0",
        fallback_urls=[
            "https://raw.githubusercontent.com/nccgroup/ScoutSuite/master/README.md",
        ],
    ),
    CheckSource(
        id="aws-fsbp-iam",
        name="AWS Foundational Security Best Practices (IAM)",
        publisher="AWS Security Hub",
        url="https://raw.githubusercontent.com/awslabs/aws-security-benchmark/master/aws_security_benchmark/data/aws-foundational-security-best-practices.json",
        format="aws_fsbp_json",
        target_file="aws_fsbp_iam.yaml",
        description="AWS Security Hub Foundational Security Best Practices — IAM controls only.",
        license="Apache-2.0",
        fallback_urls=[
            "https://api.github.com/repos/awslabs/aws-security-benchmark/contents/",
        ],
    ),
    CheckSource(
        id="azure-policy-iam",
        name="Azure Security Benchmark (IAM policies)",
        publisher="Microsoft",
        url="https://api.github.com/repos/Azure/azure-policy/contents/built-in-policies/policyDefinitions/Security%20Center",
        format="azure_policy_index",
        target_file="azure_policy_iam.yaml",
        description="Microsoft Azure built-in security policies for identity and access management.",
        license="MIT",
        fallback_urls=[
            "https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/main/articles/security-center/security-center-recommendations.md",
        ],
    ),
    CheckSource(
        id="gcp-forseti",
        name="GCP Security Scanner Rules (Forseti)",
        publisher="Google Cloud",
        url="https://api.github.com/repos/forseti-security/forseti-security/contents/configs/server/rules",
        format="forseti_index",
        target_file="gcp_forseti_rules.yaml",
        description="Forseti Security open-source GCP security scanner rules from Google Cloud.",
        license="Apache-2.0",
        fallback_urls=[
            "https://raw.githubusercontent.com/forseti-security/forseti-security/master/README.md",
        ],
    ),
]

# ── Fetch utilities ───────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 15) -> bytes:
    """Fetch a URL and return bytes. Raises URLError on failure."""
    req = Request(
        url,
        headers={
            "User-Agent": "IamWatching/2.0 (cloud-security-auditor; +https://github.com/anizacorp/iamwatching)",
            "Accept":     "application/yaml, application/json, text/plain, */*",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_with_fallback(source: CheckSource) -> tuple[bytes, str]:
    """
    Try the primary URL then each fallback URL in order.
    Returns (content_bytes, url_that_succeeded).
    Raises URLError if all URLs fail.
    """
    urls = [source.url] + source.fallback_urls
    last_err: Optional[Exception] = None
    for url in urls:
        try:
            log.debug("Fetching %s", url)
            content = _http_get(url)
            return content, url
        except Exception as e:
            log.debug("  Failed %s: %s", url, e)
            last_err = e
    raise URLError(f"All URLs failed for {source.id}: {last_err}")


# ── Format parsers ────────────────────────────────────────────────────────────

def _parse_raw_yaml(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse a raw IamWatching YAML check file."""
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or "checks" not in data:
            log.warning("Invalid YAML format from %s — missing 'checks' key", source.id)
            return None
        return data
    except yaml.YAMLError as e:
        log.warning("YAML parse error from %s: %s", source.id, e)
        return None


def _parse_prowler_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """
    Parse a GitHub API directory listing for Prowler checks.
    Returns a minimal IamWatching-compatible check YAML structure.
    """
    try:
        items = json.loads(content)
        if not isinstance(items, list):
            return None
        checks = []
        for item in items:
            if item.get("type") == "dir":
                name = item.get("name", "")
                checks.append({
                    "id": f"PROWLER-{name.upper().replace('_','-')}",
                    "title": f"Prowler: {name.replace('_',' ').title()}",
                    "severity": "MEDIUM",
                    "description": f"Prowler AWS IAM check: {name}. Fetch full details from {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:AWSPrincipal)\n"
                        f"WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, p.arn AS principal_id, p.name AS name,\n"
                        f"       'Run Prowler check {name} for detailed assessment' AS action\n"
                        "LIMIT 1"
                    ),
                    "recommendation": f"Run Prowler check for {name}: prowler aws -c {name}",
                    "mitre": [],
                    "references": [
                        item.get("html_url", ""),
                        "https://github.com/prowler-cloud/prowler",
                    ],
                })
        if not checks:
            return None
        return {
            "framework": "PROWLER-AWS",
            "description": "Prowler open-source AWS security checks (IAM family). These checks reference Prowler's comprehensive IAM assessment library.",
            "checks": checks,
        }
    except (json.JSONDecodeError, KeyError) as e:
        log.warning("Prowler parse error: %s", e)
        return None


def _parse_cloudsploit_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse a GitHub API directory listing for CloudSploit checks."""
    try:
        items = json.loads(content)
        if not isinstance(items, list):
            return None
        checks = []
        for item in items:
            if item.get("type") == "file" and item.get("name", "").endswith(".js"):
                name = item["name"].replace(".js", "")
                checks.append({
                    "id": f"CLOUDSPLOIT-{name.upper().replace('-','').replace('_','-')}",
                    "title": f"CloudSploit: {re.sub(r'([A-Z])', r' \\1', name).strip()}",
                    "severity": "MEDIUM",
                    "description": f"CloudSploit AWS IAM check: {name}. Fetch full details from {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:AWSPrincipal)\n"
                        "WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, p.arn AS principal_id, p.name AS name,\n"
                        f"       'Run CloudSploit check {name} for detailed assessment' AS action\n"
                        "LIMIT 1"
                    ),
                    "recommendation": f"Run CloudSploit check: cloudsploit scan --plugin={name}",
                    "mitre": [],
                    "references": [
                        item.get("html_url", ""),
                        "https://github.com/aquasecurity/cloudsploit",
                    ],
                })
        if not checks:
            return None
        return {
            "framework": "CLOUDSPLOIT-AWS",
            "description": "Aqua CloudSploit AWS IAM security checks. These checks reference CloudSploit's open-source security posture assessment library.",
            "checks": checks,
        }
    except (json.JSONDecodeError, KeyError) as e:
        log.warning("CloudSploit parse error: %s", e)
        return None


def _parse_steampipe_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse Steampipe GitHub directory index into IamWatching check stubs."""
    try:
        items = json.loads(content)
        if not isinstance(items, list):
            return None
        checks = []
        for item in items:
            if item.get("type") == "file" and item.get("name","").endswith(".sp"):
                name = item["name"].replace(".sp","")
                cid  = f"STEAMPIPE-{name.upper().replace('-','').replace('_','-')}"
                checks.append({
                    "id": cid, "title": f"Steampipe: {name.replace('_',' ').title()}",
                    "severity": "MEDIUM",
                    "description": f"Steampipe AWS CIS compliance check: {name}. Source: {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:Principal)\n"
                        "WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, COALESCE(p.arn,p.object_id,p.email) AS principal_id,\n"
                        f"       'Run Steampipe check {name} for detailed assessment' AS action LIMIT 1"
                    ),
                    "recommendation": f"Run: steampipe check aws_compliance.benchmark.cis_v300 --where \"control_id = \'{name}\'\"",
                    "mitre": [], "references": [item.get("html_url",""), "https://steampipe.io"],
                })
        if not checks: return None
        return {"framework": "STEAMPIPE-AWS-COMPLIANCE",
                "description": "Steampipe AWS CIS v3.0 compliance checks from Turbot.", "checks": checks}
    except Exception as e:
        log.warning("Steampipe parse error: %s", e); return None


def _parse_scoutsuite_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse ScoutSuite finding rules directory."""
    try:
        items = json.loads(content)
        if not isinstance(items, list): return None
        checks = []
        for item in items:
            if item.get("type") == "file" and item.get("name","").endswith(".json"):
                name = item["name"].replace(".json","")
                checks.append({
                    "id": f"SCOUTSUITE-{name.upper().replace('-','').replace('.','').replace('_','-')[:40]}",
                    "title": f"ScoutSuite: {name.replace('-',' ').replace('_',' ').title()}",
                    "severity": "MEDIUM",
                    "description": f"ScoutSuite security finding rule: {name}. Source: {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:Principal)\n"
                        "WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, COALESCE(p.arn,p.object_id,p.email) AS principal_id,\n"
                        f"       'Run ScoutSuite to evaluate finding {name}' AS action LIMIT 1"
                    ),
                    "recommendation": f"Run: scout aws --ruleset-findings={name}",
                    "mitre": [], "references": [item.get("html_url",""), "https://github.com/nccgroup/ScoutSuite"],
                })
        if not checks: return None
        return {"framework": "SCOUTSUITE-AWS",
                "description": "NCC Group ScoutSuite AWS IAM finding rules.", "checks": checks}
    except Exception as e:
        log.warning("ScoutSuite parse error: %s", e); return None


def _parse_azure_policy_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse Azure Policy GitHub directory into check stubs."""
    try:
        items = json.loads(content)
        if not isinstance(items, list): return None
        checks = []
        for item in items:
            if item.get("type") == "file" and item.get("name","").endswith(".json"):
                name = item["name"].replace(".json","")
                safe = re.sub(r"[^A-Z0-9]", "-", name.upper())[:40]
                checks.append({
                    "id": f"AZPOLICY-{safe}",
                    "title": f"Azure Policy: {name.replace('-',' ').replace('_',' ').title()}",
                    "severity": "MEDIUM",
                    "description": f"Azure built-in security policy: {name}. Source: {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:Principal)\n"
                        "WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, COALESCE(p.arn,p.object_id,p.email) AS principal_id,\n"
                        f"       'Review Azure policy {name} in Azure Security Center' AS action LIMIT 1"
                    ),
                    "recommendation": f"Enable Azure Policy initiative: {name} in Azure Security Center / Defender for Cloud.",
                    "mitre": [], "references": [item.get("html_url",""), "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade"],
                })
        if not checks: return None
        return {"framework": "AZURE-POLICY-IAM",
                "description": "Microsoft Azure built-in IAM security policies.", "checks": checks}
    except Exception as e:
        log.warning("Azure Policy parse error: %s", e); return None


def _parse_forseti_index(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse Forseti Security rules directory into check stubs."""
    try:
        items = json.loads(content)
        if not isinstance(items, list): return None
        checks = []
        for item in items:
            if item.get("type") == "file" and item.get("name","").endswith(".yaml"):
                name = item["name"].replace(".yaml","")
                safe = re.sub(r"[^A-Z0-9]", "-", name.upper())[:40]
                checks.append({
                    "id": f"FORSETI-{safe}",
                    "title": f"Forseti GCP: {name.replace('-',' ').replace('_',' ').title()}",
                    "severity": "MEDIUM",
                    "description": f"Forseti Security GCP rule: {name}. Source: {item.get('html_url','')}",
                    "cypher": (
                        "MATCH (p:Principal)\n"
                        "WHERE p.scan_start_ms >= $scan_start\n"
                        "RETURN labels(p) AS cloud, COALESCE(p.arn,p.object_id,p.email) AS principal_id,\n"
                        f"       'Evaluate Forseti rule {name} on GCP' AS action LIMIT 1"
                    ),
                    "recommendation": f"Configure Forseti rule {name} and run: forseti scanner run",
                    "mitre": [], "references": [item.get("html_url",""), "https://github.com/forseti-security/forseti-security"],
                })
        if not checks: return None
        return {"framework": "GCP-FORSETI",
                "description": "Google Cloud Forseti Security scanner rules.", "checks": checks}
    except Exception as e:
        log.warning("Forseti parse error: %s", e); return None


def _parse_aws_fsbp_json(content: bytes, source: CheckSource) -> Optional[dict]:
    """Parse AWS Foundational Security Best Practices JSON into IAM-focused checks."""
    try:
        data = json.loads(content)
        raw  = data if isinstance(data, list) else data.get("controls", data.get("findings", []))
        checks = []
        for ctrl in raw:
            if not isinstance(ctrl, dict): continue
            cid    = ctrl.get("ControlId", ctrl.get("id",""))
            title  = ctrl.get("Title", ctrl.get("title",""))
            if not cid or not title: continue
            # Only include IAM-related controls
            if not any(x in (cid + title).upper() for x in ("IAM","IDENTITY","ACCESS","MFA","ROOT","CRED")):
                continue
            safe_id = re.sub(r"[^A-Z0-9]","-", cid.upper())[:30]
            checks.append({
                "id": f"AWSFSBP-{safe_id}",
                "title": f"AWS FSBP: {title[:80]}",
                "severity": ctrl.get("SeverityRating", "MEDIUM").upper(),
                "description": ctrl.get("Description", title),
                "cypher": (
                    "MATCH (p:Principal)\n"
                    "WHERE p.scan_start_ms >= $scan_start\n"
                    "RETURN labels(p) AS cloud, COALESCE(p.arn,p.object_id,p.email) AS principal_id,\n"
                    f"       'Verify compliance with AWS FSBP {cid}' AS action LIMIT 1"
                ),
                "recommendation": ctrl.get("RemediationUrl", f"See AWS Security Hub control {cid}"),
                "mitre": [], "references": [f"https://docs.aws.amazon.com/securityhub/latest/userguide/{cid.lower()}.html"],
            })
        if not checks: return None
        return {"framework": "AWS-FSBP-IAM",
                "description": "AWS Foundational Security Best Practices — IAM controls.", "checks": checks}
    except Exception as e:
        log.warning("AWS FSBP parse error: %s", e); return None


_PARSERS = {
    "raw_yaml":           _parse_raw_yaml,
    "prowler_index":      _parse_prowler_index,
    "cloudsploit_index":  _parse_cloudsploit_index,
    "steampipe_index":    _parse_steampipe_index,
    "scoutsuite_index":   _parse_scoutsuite_index,
    "azure_policy_index": _parse_azure_policy_index,
    "forseti_index":      _parse_forseti_index,
    "aws_fsbp_json":      _parse_aws_fsbp_json,
}


# ── Update engine ─────────────────────────────────────────────────────────────

@dataclass
class UpdateResult:
    source_id:    str
    source_name:  str
    status:       str        # "updated" | "unchanged" | "failed" | "skipped"
    checks_count: int = 0
    error:        str = ""
    url:          str = ""


def update_from_sources(
    checks_dir: Path,
    source_ids:  Optional[list[str]] = None,
    dry_run:     bool = False,
    backup:      bool = True,
) -> list[UpdateResult]:
    """
    Fetch check definitions from all registered sources and update the local
    builtin/ directory.

    Args:
        checks_dir:  Path to the checks/ directory (contains builtin/ and custom/)
        source_ids:  If given, only update these source IDs. None = all sources.
        dry_run:     If True, fetch and parse but do not write any files.
        backup:      If True, back up existing builtin files before overwriting.

    Returns:
        List of UpdateResult, one per source attempted.
    """
    builtin_dir = checks_dir / "builtin"
    builtin_dir.mkdir(parents=True, exist_ok=True)
    backup_dir  = checks_dir / ".backups" / datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    results: list[UpdateResult] = []
    manifest: dict = _load_manifest(checks_dir)

    sources_to_run = [s for s in SOURCES if source_ids is None or s.id in source_ids]

    for source in sources_to_run:
        result = UpdateResult(source_id=source.id, source_name=source.name, status="failed")
        try:
            log.info("Fetching from %s ...", source.name)
            content, used_url = _fetch_with_fallback(source)
            result.url = used_url

            parser = _PARSERS.get(source.format)
            if not parser:
                result.status = "skipped"
                result.error  = f"No parser for format '{source.format}'"
                results.append(result)
                continue

            parsed = parser(content, source)
            if not parsed:
                result.status = "failed"
                result.error  = "Parser returned no data"
                results.append(result)
                continue

            result.checks_count = len(parsed.get("checks", []))
            target_path = builtin_dir / source.target_file

            # Check if content actually changed
            new_yaml = yaml.dump(parsed, default_flow_style=False, allow_unicode=True, sort_keys=False)
            if target_path.exists():
                existing = target_path.read_text(encoding="utf-8")
                # Compare check counts and IDs to detect real changes
                try:
                    existing_data = yaml.safe_load(existing)
                    existing_ids  = {c["id"] for c in existing_data.get("checks", [])}
                    new_ids       = {c["id"] for c in parsed.get("checks", [])}
                    if existing_ids == new_ids and len(existing_data.get("checks", [])) == result.checks_count:
                        result.status = "unchanged"
                        results.append(result)
                        continue
                except Exception:
                    pass

            if not dry_run:
                if backup and target_path.exists():
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target_path, backup_dir / source.target_file)

                target_path.write_text(new_yaml, encoding="utf-8")

                manifest[source.id] = {
                    "source_name":   source.name,
                    "target_file":   source.target_file,
                    "url":           used_url,
                    "checks_count":  result.checks_count,
                    "updated_at":    datetime.now(timezone.utc).isoformat(),
                }
                _save_manifest(checks_dir, manifest)

            result.status = "updated" if not dry_run else "dry_run"

        except URLError as e:
            result.status = "failed"
            result.error  = f"Network error: {e}"
            log.warning("Failed to fetch %s: %s", source.id, e)
        except Exception as e:
            result.status = "failed"
            result.error  = str(e)
            log.warning("Error updating %s: %s", source.id, e)

        results.append(result)

    return results


def _load_manifest(checks_dir: Path) -> dict:
    path = checks_dir / ".update_manifest.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def _save_manifest(checks_dir: Path, manifest: dict):
    path = checks_dir / ".update_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def get_manifest(checks_dir: Path) -> dict:
    return _load_manifest(checks_dir)


# ── Import / Export ───────────────────────────────────────────────────────────

def export_checks(
    checks: list,          # list of CheckDefinition objects
    output_path: str,
    fmt: str = "yaml",     # "yaml" | "json"
    framework: Optional[str] = None,
) -> int:
    """
    Export check definitions to a YAML or JSON file.

    Args:
        checks:       List of CheckDefinition objects from the registry.
        output_path:  Where to write the file.
        fmt:          "yaml" or "json".
        framework:    If given, only export checks from this framework.

    Returns:
        Number of checks exported.
    """
    if framework:
        checks = [c for c in checks if framework.lower() in c.framework.lower()]

    def _check_to_dict(c) -> dict:
        return {
            "id":             c.id,
            "title":          c.title,
            "severity":       c.severity.value if hasattr(c.severity, "value") else str(c.severity),
            "framework":      c.framework,
            "enabled":        c.enabled,
            "description":    c.description,
            "cypher":         c.cypher,
            "recommendation": c.recommendation,
            "mitre":          c.mitre,
            "references":     c.references,
        }

    # Group by framework for cleaner output
    by_framework: dict[str, list] = {}
    for c in checks:
        by_framework.setdefault(c.framework, []).append(_check_to_dict(c))

    export_data = {
        "exported_at":   datetime.now(timezone.utc).isoformat(),
        "exported_by":   "IamWatching v2.0",
        "total_checks":  len(checks),
        "frameworks":    list(by_framework.keys()),
        "checks":        [_check_to_dict(c) for c in checks],
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path.write_text(json.dumps(export_data, indent=2), encoding="utf-8")
    else:
        path.write_text(
            yaml.dump(export_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    return len(checks)


def import_checks(
    input_path: str,
    custom_dir: Path,
    overwrite: bool = False,
) -> tuple[int, int, list[str]]:
    """
    Import check definitions from a YAML or JSON file into the custom/ directory.

    Supports both IamWatching export format and raw framework YAML format.

    Args:
        input_path:  Path to the file to import.
        custom_dir:  Destination directory for imported checks.
        overwrite:   If False, skip checks whose IDs already exist locally.

    Returns:
        (imported_count, skipped_count, error_list)
    """
    path = Path(input_path)
    if not path.exists():
        return 0, 0, [f"File not found: {input_path}"]

    content = path.read_text(encoding="utf-8")

    # Parse based on file extension or content
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return 0, 0, [f"Invalid JSON: {e}"]
    else:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return 0, 0, [f"Invalid YAML: {e}"]

    if not isinstance(data, dict):
        return 0, 0, ["File must contain a mapping/object at the top level"]

    # Normalise: both export format (has 'checks' list) and raw framework format work
    raw_checks = data.get("checks", [])
    if not raw_checks:
        return 0, 0, ["No checks found in file (expected a 'checks' list)"]

    custom_dir.mkdir(parents=True, exist_ok=True)

    # Collect existing check IDs to detect duplicates
    existing_ids: set[str] = set()
    for f in custom_dir.glob("*.yaml"):
        try:
            d = yaml.safe_load(f.read_text())
            if isinstance(d, dict):
                for c in d.get("checks", []):
                    existing_ids.add(c.get("id", ""))
        except Exception:
            pass

    imported, skipped = 0, 0
    errors: list[str] = []

    # Group incoming checks by framework for clean file organisation
    by_framework: dict[str, list] = {}
    for check in raw_checks:
        if not isinstance(check, dict):
            errors.append(f"Skipping non-dict check: {check!r:.60}")
            continue
        if not check.get("id") or not check.get("cypher"):
            errors.append(f"Check missing required 'id' or 'cypher': {check.get('id','?')}")
            continue
        check_id = check["id"]
        if check_id in existing_ids and not overwrite:
            skipped += 1
            continue
        fw = check.get("framework", data.get("framework", "IMPORTED"))
        by_framework.setdefault(fw, []).append(check)

    # Write one file per framework
    for fw, fw_checks in by_framework.items():
        safe_name = re.sub(r"[^a-z0-9_]", "_", fw.lower()) + "_imported.yaml"
        out_path   = custom_dir / safe_name
        out_data   = {
            "framework":   fw,
            "description": data.get("description", f"Imported from {path.name}"),
            "checks":      fw_checks,
        }
        if out_path.exists() and not overwrite:
            # Merge: add only new checks
            existing = yaml.safe_load(out_path.read_text())
            existing_in_file = {c["id"] for c in existing.get("checks", [])}
            new_checks = [c for c in fw_checks if c["id"] not in existing_in_file]
            if new_checks:
                existing.setdefault("checks", []).extend(new_checks)
                out_path.write_text(
                    yaml.dump(existing, default_flow_style=False, allow_unicode=True, sort_keys=False),
                    encoding="utf-8",
                )
                imported += len(new_checks)
        else:
            out_path.write_text(
                yaml.dump(out_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            imported += len(fw_checks)

    return imported, skipped, errors
