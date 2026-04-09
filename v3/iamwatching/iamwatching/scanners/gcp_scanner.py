"""
GCP IAM Scanner
===============
All Google Cloud SDK imports are deferred inside method bodies.
Importing this module never fails due to missing GCP packages.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

CROSS_CLOUD_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "aws_secret":     re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "azure_client_secret": re.compile(r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*['\"]?([A-Za-z0-9\-._~]{20,})"),
    "azure_tenant_id":     re.compile(r"(?i)AZURE_TENANT_ID\s*[=:]\s*['\"]?([0-9a-fA-F\-]{36})"),
}


def _scan_for_creds(text, source_resource, source_type, project_id, location):
    found = []
    for cred_type, pattern in CROSS_CLOUD_PATTERNS.items():
        for match in pattern.findall(text):
            raw = match if isinstance(match, str) else (match[-1] if match else "")
            if not raw:
                continue
            target = "aws" if "aws" in cred_type else "azure"
            found.append(DiscoveredCredential(
                source_cloud="gcp", target_cloud=target, cred_type=cred_type,
                raw_value=raw[:120], source_resource=source_resource,
                source_resource_type=source_type,
                project_id=project_id, location=location,
            ))
    return found


@dataclass
class DiscoveredCredential:
    source_cloud: str
    target_cloud: str
    cred_type: str
    raw_value: str
    source_resource: str
    source_resource_type: str
    project_id: str
    location: str


@dataclass
class GCPPrincipal:
    email: str
    principal_type: str
    project_id: str
    display_name: str
    iam_bindings: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class GCPResource:
    resource_id: str
    resource_type: str
    project_id: str
    location: str
    name: str
    env_vars: dict = field(default_factory=dict)
    discovered_creds: list = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class GCPScanResult:
    project_id: str
    principals: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    project_iam_policy: dict = field(default_factory=dict)
    discovered_credentials: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class GCPScanner:
    """
    Async GCP IAM scanner.
    All google.* imports happen inside async methods — safe to import without SDK.
    """

    def __init__(self, project_id: str, locations: Optional[list[str]] = None):
        self.project_id = project_id
        self.locations  = locations or ["us-central1"]

    async def _run_sync(self, fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))

    def _default_credentials(self):
        import google.auth  # noqa: PLC0415
        creds, _ = google.auth.default()
        return creds

    async def _get_project_iam_policy(self) -> dict:
        from googleapiclient.discovery import build  # noqa: PLC0415
        creds = self._default_credentials()
        crm = build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)
        return await self._run_sync(
            crm.projects().getIamPolicy(resource=self.project_id, body={}).execute
        )

    async def _list_service_accounts(self) -> list[GCPPrincipal]:
        from googleapiclient.discovery import build  # noqa: PLC0415
        creds = self._default_credentials()
        iam = build("iam", "v1", credentials=creds, cache_discovery=False)
        principals = []
        try:
            result = await self._run_sync(
                iam.projects().serviceAccounts().list(
                    name=f"projects/{self.project_id}"
                ).execute
            )
            for sa in result.get("accounts", []):
                keys = []
                try:
                    kr = await self._run_sync(
                        iam.projects().serviceAccounts().keys().list(name=sa["name"]).execute
                    )
                    keys = kr.get("keys", [])
                except Exception:
                    pass
                principals.append(GCPPrincipal(
                    email=sa["email"], principal_type="serviceAccount",
                    project_id=self.project_id,
                    display_name=sa.get("displayName", ""),
                    keys=keys,
                    metadata={
                        "unique_id": sa.get("uniqueId"),
                        "disabled": sa.get("disabled", False),
                    },
                ))
        except Exception as e:
            log.warning("SA list failed: %s", e)
        return principals

    async def _extract_non_sa_principals(self, policy: dict) -> list[GCPPrincipal]:
        principals: dict[str, GCPPrincipal] = {}
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                parts = member.split(":", 1)
                if len(parts) != 2:
                    continue
                ptype, email = parts
                if ptype == "serviceAccount":
                    continue
                if email not in principals:
                    principals[email] = GCPPrincipal(
                        email=email, principal_type=ptype,
                        project_id=self.project_id, display_name=email,
                    )
                principals[email].iam_bindings.append(
                    {"role": role, "resource": f"projects/{self.project_id}"}
                )
        return list(principals.values())

    async def _scan_cloud_functions(self, location: str) -> list[GCPResource]:
        resources = []
        try:
            from google.cloud import functions_v1  # noqa: PLC0415
            creds = self._default_credentials()
            client = functions_v1.CloudFunctionsServiceAsyncClient(credentials=creds)
            parent  = f"projects/{self.project_id}/locations/{location}"
            request = functions_v1.ListFunctionsRequest(parent=parent)
            async for fn in await client.list_functions(request=request):
                env_vars = dict(fn.environment_variables)
                creds_found = _scan_for_creds(
                    json.dumps(env_vars), fn.name,
                    "cloudfunctions.googleapis.com/Function",
                    self.project_id, location,
                )
                resources.append(GCPResource(
                    resource_id=fn.name,
                    resource_type="cloudfunctions.googleapis.com/Function",
                    project_id=self.project_id, location=location,
                    name=fn.name.split("/")[-1],
                    env_vars=env_vars, discovered_creds=creds_found,
                    metadata={"runtime": fn.runtime,
                              "service_account_email": fn.service_account_email},
                ))
        except Exception as e:
            log.warning("Cloud Functions scan failed %s/%s: %s", self.project_id, location, e)
        return resources

    async def _scan_cloud_run(self, location: str) -> list[GCPResource]:
        resources = []
        try:
            from google.cloud import run_v2  # noqa: PLC0415
            creds = self._default_credentials()
            client  = run_v2.ServicesAsyncClient(credentials=creds)
            parent  = f"projects/{self.project_id}/locations/{location}"
            request = run_v2.ListServicesRequest(parent=parent)
            async for svc in await client.list_services(request=request):
                env_vars: dict = {}
                for container in (svc.template.containers or []):
                    for ev in container.env:
                        env_vars[f"{container.name}/{ev.name}"] = ev.value or "[secret-ref]"
                creds_found = _scan_for_creds(
                    json.dumps(env_vars), svc.name,
                    "run.googleapis.com/Service",
                    self.project_id, location,
                )
                resources.append(GCPResource(
                    resource_id=svc.name,
                    resource_type="run.googleapis.com/Service",
                    project_id=self.project_id, location=location,
                    name=svc.name.split("/")[-1],
                    env_vars=env_vars, discovered_creds=creds_found,
                    metadata={"service_account": svc.template.service_account},
                ))
        except Exception as e:
            log.warning("Cloud Run scan failed %s/%s: %s", self.project_id, location, e)
        return resources

    async def _scan_compute(self, location: str) -> list[GCPResource]:
        resources = []
        try:
            from google.cloud.compute_v1 import InstancesClient  # noqa: PLC0415
            creds  = self._default_credentials()
            client = InstancesClient(credentials=creds)
            for inst in await self._run_sync(
                lambda: list(client.list(project=self.project_id, zone=location))
            ):
                startup = ""
                for item in (inst.metadata.items if inst.metadata else []):
                    if item.key in ("startup-script", "user-data", "startup-script-url"):
                        startup += item.value or ""
                resource_id = (
                    f"projects/{self.project_id}/zones/{location}/instances/{inst.name}"
                )
                creds_found = _scan_for_creds(
                    startup, resource_id,
                    "compute.googleapis.com/Instance",
                    self.project_id, location,
                )
                resources.append(GCPResource(
                    resource_id=resource_id,
                    resource_type="compute.googleapis.com/Instance",
                    project_id=self.project_id, location=location,
                    name=inst.name,
                    env_vars={"startup_script": startup[:500]},
                    discovered_creds=creds_found,
                    tags=dict(inst.labels or {}),
                    metadata={"status": inst.status, "machine_type": inst.machine_type},
                ))
        except Exception as e:
            log.warning("Compute scan failed %s/%s: %s", self.project_id, location, e)
        return resources

    async def scan(self) -> GCPScanResult:
        result = GCPScanResult(project_id=self.project_id)
        log.info("GCP scan: project=%s locations=%s", self.project_id, self.locations)

        policy, service_accounts = await asyncio.gather(
            self._get_project_iam_policy(),
            self._list_service_accounts(),
        )
        result.project_iam_policy = policy
        other_principals = await self._extract_non_sa_principals(policy)

        sa_map = {sa.email: sa for sa in service_accounts}
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:"):
                    email = member.split(":", 1)[1]
                    if email in sa_map:
                        sa_map[email].iam_bindings.append(
                            {"role": role, "resource": f"projects/{self.project_id}"}
                        )
        result.principals = service_accounts + other_principals

        location_tasks = [
            asyncio.gather(
                self._scan_cloud_functions(loc),
                self._scan_cloud_run(loc),
                self._scan_compute(loc),
                return_exceptions=True,
            )
            for loc in self.locations
        ]
        location_results = await asyncio.gather(*location_tasks, return_exceptions=True)
        for lr in location_results:
            if not isinstance(lr, Exception):
                for sub in lr:
                    if isinstance(sub, list):
                        result.resources.extend(sub)

        for r in result.resources:
            result.discovered_credentials.extend(r.discovered_creds)

        log.info("GCP done: %d principals, %d resources, %d creds",
                 len(result.principals), len(result.resources),
                 len(result.discovered_credentials))
        return result
