"""
Azure IAM Scanner
=================
All Azure SDK imports are deferred inside method bodies.
Importing this module never fails due to missing Azure packages.
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
    "gcp_service_account": re.compile(r'"type"\s*:\s*"service_account"'),
    "gcp_api_key":    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
}


def _scan_for_creds(text, source_resource, source_type, subscription_id, location):
    found = []
    for cred_type, pattern in CROSS_CLOUD_PATTERNS.items():
        for match in pattern.findall(text):
            raw = match if isinstance(match, str) else (match[-1] if match else "")
            if not raw:
                continue
            target = "aws" if "aws" in cred_type else "gcp"
            found.append(DiscoveredCredential(
                source_cloud="azure", target_cloud=target, cred_type=cred_type,
                raw_value=raw[:120], source_resource=source_resource,
                source_resource_type=source_type, subscription_id=subscription_id,
                location=location,
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
    subscription_id: str
    location: str


@dataclass
class AzurePrincipal:
    object_id: str
    principal_type: str
    display_name: str
    upn: Optional[str]
    app_id: Optional[str]
    role_assignments: list = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class AzureResource:
    resource_id: str
    resource_type: str
    subscription_id: str
    resource_group: str
    location: str
    name: str
    env_vars: dict = field(default_factory=dict)
    discovered_creds: list = field(default_factory=list)
    tags: dict = field(default_factory=dict)


@dataclass
class AzureScanResult:
    subscription_id: str
    tenant_id: str
    principals: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    role_definitions: list = field(default_factory=list)
    discovered_credentials: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class AzureScanner:
    """
    Async Azure IAM scanner.
    All azure.* imports happen inside async methods — safe to import without SDK.
    """

    def __init__(self, subscription_id: str, tenant_id: str):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id

    def _credential(self):
        from azure.identity.aio import DefaultAzureCredential  # noqa: PLC0415
        return DefaultAzureCredential()

    async def _list_aad_users(self, graph_client) -> list[AzurePrincipal]:
        principals = []
        try:
            users = await graph_client.users.get()
            for u in (users.value or []):
                principals.append(AzurePrincipal(
                    object_id=u.id, principal_type="User",
                    display_name=u.display_name or "", upn=u.user_principal_name,
                    app_id=None,
                    metadata={"account_enabled": u.account_enabled,
                              "job_title": u.job_title},
                ))
        except Exception as e:
            log.warning("AAD user list failed: %s", e)
        return principals

    async def _list_service_principals(self, graph_client) -> list[AzurePrincipal]:
        principals = []
        try:
            sps = await graph_client.service_principals.get()
            for sp in (sps.value or []):
                principals.append(AzurePrincipal(
                    object_id=sp.id, principal_type="ServicePrincipal",
                    display_name=sp.display_name or "", upn=None,
                    app_id=sp.app_id,
                    metadata={"service_principal_type": sp.service_principal_type},
                ))
        except Exception as e:
            log.warning("AAD SP list failed: %s", e)
        return principals

    async def _list_role_assignments(self, authz_client) -> list[dict]:
        assignments = []
        try:
            scope = f"/subscriptions/{self.subscription_id}"
            async for ra in authz_client.role_assignments.list_for_scope(scope):
                assignments.append({
                    "id": ra.id, "principal_id": ra.principal_id,
                    "principal_type": ra.principal_type,
                    "role_definition_id": ra.role_definition_id,
                    "scope": ra.scope, "condition": ra.condition,
                })
        except Exception as e:
            log.warning("Role assignment list failed: %s", e)
        return assignments

    async def _list_role_definitions(self, authz_client) -> list[dict]:
        defs = []
        try:
            scope = f"/subscriptions/{self.subscription_id}"
            async for rd in authz_client.role_definitions.list(scope):
                defs.append({
                    "id": rd.id, "name": rd.role_name, "type": rd.role_type,
                    "permissions": [
                        {"actions": p.actions, "not_actions": p.not_actions}
                        for p in (rd.permissions or [])
                    ],
                })
        except Exception as e:
            log.warning("Role def list failed: %s", e)
        return defs

    async def _scan_function_apps(self, web_client, rg_name: str) -> list[AzureResource]:
        resources = []
        try:
            async for app in web_client.web_apps.list_by_resource_group(rg_name):
                if not (app.kind and "functionapp" in app.kind.lower()):
                    continue
                env_vars: dict = {}
                try:
                    settings = await web_client.web_apps.list_application_settings(rg_name, app.name)
                    env_vars = settings.properties or {}
                except Exception:
                    pass
                creds = _scan_for_creds(
                    json.dumps(env_vars), app.id, "microsoft.web/sites",
                    self.subscription_id, app.location or "",
                )
                resources.append(AzureResource(
                    resource_id=app.id,
                    resource_type="microsoft.web/sites/functionapp",
                    subscription_id=self.subscription_id,
                    resource_group=rg_name, location=app.location or "",
                    name=app.name, env_vars=env_vars,
                    discovered_creds=creds, tags=app.tags or {},
                ))
        except Exception as e:
            log.warning("Function app scan failed RG=%s: %s", rg_name, e)
        return resources

    async def _scan_vms(self, compute_client, rg_name: str) -> list[AzureResource]:
        resources = []
        try:
            async for vm in compute_client.virtual_machines.list(rg_name):
                combined = ""
                try:
                    detail = await compute_client.virtual_machines.get(rg_name, vm.name)
                    if detail.os_profile:
                        combined += detail.os_profile.custom_data or ""
                    async for ext in compute_client.virtual_machine_extensions.list(rg_name, vm.name):
                        if ext.virtual_machine_extension_type in (
                            "CustomScript", "CustomScriptExtension", "cloud-init"
                        ):
                            combined += json.dumps(ext.settings or {})
                except Exception:
                    pass
                creds = _scan_for_creds(
                    combined, vm.id, "microsoft.compute/virtualmachines",
                    self.subscription_id, vm.location or "",
                )
                resources.append(AzureResource(
                    resource_id=vm.id,
                    resource_type="microsoft.compute/virtualmachines",
                    subscription_id=self.subscription_id,
                    resource_group=rg_name, location=vm.location or "",
                    name=vm.name,
                    env_vars={"custom_data": combined[:500]},
                    discovered_creds=creds, tags=vm.tags or {},
                ))
        except Exception as e:
            log.warning("VM scan failed RG=%s: %s", rg_name, e)
        return resources

    async def scan(self) -> AzureScanResult:
        from azure.mgmt.authorization.aio import AuthorizationManagementClient  # noqa: PLC0415
        from azure.mgmt.compute.aio import ComputeManagementClient              # noqa: PLC0415
        from azure.mgmt.resource.aio import ResourceManagementClient            # noqa: PLC0415
        from azure.mgmt.web.aio import WebSiteManagementClient                  # noqa: PLC0415
        from msgraph import GraphServiceClient                                  # noqa: PLC0415

        result = AzureScanResult(
            subscription_id=self.subscription_id, tenant_id=self.tenant_id
        )
        log.info("Azure scan: subscription=%s", self.subscription_id)

        cred = self._credential()
        graph_client = GraphServiceClient(
            credentials=cred,
            scopes=["https://graph.microsoft.com/.default"],
        )

        async with (
            AuthorizationManagementClient(cred, self.subscription_id) as authz,
            ResourceManagementClient(cred, self.subscription_id) as resource,
            ComputeManagementClient(cred, self.subscription_id) as compute,
            WebSiteManagementClient(cred, self.subscription_id) as web,
        ):
            users, sps, role_assignments, role_defs = await asyncio.gather(
                self._list_aad_users(graph_client),
                self._list_service_principals(graph_client),
                self._list_role_assignments(authz),
                self._list_role_definitions(authz),
            )
            result.principals     = users + sps
            result.role_definitions = role_defs

            # Attach role assignments to principals
            ra_map: dict = {}
            for ra in role_assignments:
                ra_map.setdefault(ra.get("principal_id"), []).append(ra)
            for p in result.principals:
                p.role_assignments = ra_map.get(p.object_id, [])

            # Per-RG resource scans
            rg_tasks = []
            async for rg in resource.resource_groups.list():
                rg_tasks.append(asyncio.gather(
                    self._scan_function_apps(web, rg.name),
                    self._scan_vms(compute, rg.name),
                    return_exceptions=True,
                ))
            rg_results = await asyncio.gather(*rg_tasks, return_exceptions=True)
            for rr in rg_results:
                if not isinstance(rr, Exception):
                    for sub in rr:
                        if isinstance(sub, list):
                            result.resources.extend(sub)

        for r in result.resources:
            result.discovered_credentials.extend(r.discovered_creds)

        log.info("Azure done: %d principals, %d resources, %d creds",
                 len(result.principals), len(result.resources),
                 len(result.discovered_credentials))
        return result
