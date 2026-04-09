"""
AWS IAM Scanner
===============
All boto3/aioboto3 imports are deferred inside method bodies so that
importing this module never fails even when the AWS SDK is not installed.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ── Cross-cloud credential patterns ──────────────────────────────────────────
# GCP API keys: AIza + 35 alphanumeric/-/_ = 39 chars total.
# Use {32,40} to tolerate minor variation in test fixtures and real keys.
CROSS_CLOUD_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(
        r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])"
    ),
    "gcp_service_account": re.compile(
        r'"type"\s*:\s*"service_account"'
    ),
    "gcp_api_key": re.compile(
        r"AIza[0-9A-Za-z\-_]{32,40}"
    ),
    "azure_client_secret": re.compile(
        r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*['\"]?([A-Za-z0-9\-._~]{20,})"
    ),
    "azure_tenant_id": re.compile(
        r"(?i)AZURE_TENANT_ID\s*[=:]\s*['\"]?([0-9a-fA-F\-]{36})"
    ),
}


def _scan_for_creds(
    text: str,
    source_resource: str,
    source_type: str,
    account_id: str,
    region: str,
) -> list[DiscoveredCredential]:
    """Scan arbitrary text for cross-cloud credential patterns."""
    found: list[DiscoveredCredential] = []
    for cred_type, pattern in CROSS_CLOUD_PATTERNS.items():
        for match in pattern.finditer(text):
            # For patterns with a capture group (azure_*) use group(1),
            # otherwise use the full match string.
            try:
                raw = match.group(1)
            except IndexError:
                raw = match.group(0)
            if not raw:
                continue
            target = (
                "azure" if "azure" in cred_type
                else "gcp" if "gcp" in cred_type
                else "aws"
            )
            found.append(DiscoveredCredential(
                source_cloud="aws",
                target_cloud=target,
                cred_type=cred_type,
                raw_value=raw[:120],
                source_resource=source_resource,
                source_resource_type=source_type,
                account_id=account_id,
                region=region,
            ))
    return found


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DiscoveredCredential:
    source_cloud: str
    target_cloud: str
    cred_type: str
    raw_value: str
    source_resource: str
    source_resource_type: str
    account_id: str
    region: str


@dataclass
class AWSPrincipal:
    arn: str
    principal_type: str
    account_id: str
    name: str
    attached_policies: list = field(default_factory=list)
    inline_policies:   list = field(default_factory=list)
    tags:     dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class AWSResource:
    arn: str
    resource_type: str
    account_id: str
    region: str
    name: str
    resource_policy:  Optional[dict] = None
    env_vars:         dict = field(default_factory=dict)
    discovered_creds: list = field(default_factory=list)
    tags:             dict = field(default_factory=dict)


@dataclass
class AWSScanResult:
    account_id: str
    region: str
    principals:             list = field(default_factory=list)
    resources:              list = field(default_factory=list)
    managed_policies:       list = field(default_factory=list)
    discovered_credentials: list = field(default_factory=list)
    errors:                 list = field(default_factory=list)


# ── Scanner ───────────────────────────────────────────────────────────────────

class AWSScanner:
    def __init__(
        self,
        profile: Optional[str] = None,
        regions: Optional[list[str]] = None,
        _session_factory=None,
    ):
        self.profile = profile
        self.regions = regions or ["us-east-1"]
        self._session_factory = _session_factory  # injectable for testing

    def _session(self):
        if self._session_factory is not None:
            # Injected session (used in tests to provide a sync boto3 wrapper)
            return self._session_factory()
        import aioboto3  # noqa: PLC0415
        return aioboto3.Session(profile_name=self.profile)

    async def get_account_id(self) -> str:
        session = self._session()
        async with session.client("sts") as sts:
            return (await sts.get_caller_identity())["Account"]

    async def _list_users(self, iam, account_id: str) -> list[AWSPrincipal]:
        principals: list[AWSPrincipal] = []
        async for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                attached, inline = await asyncio.gather(
                    self._user_attached(iam, u["UserName"]),
                    self._user_inline(iam, u["UserName"]),
                )
                principals.append(AWSPrincipal(
                    arn=u["Arn"], principal_type="User",
                    account_id=account_id, name=u["UserName"],
                    attached_policies=attached, inline_policies=inline,
                    tags={t["Key"]: t["Value"] for t in u.get("Tags", [])},
                    metadata={"create_date": str(u.get("CreateDate", "")),
                              "path": u.get("Path", "/")},
                ))
        return principals

    async def _user_attached(self, iam, username: str) -> list:
        out = []
        async for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
            out.extend(page["AttachedPolicies"])
        return out

    async def _user_inline(self, iam, username: str) -> list:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        out = []
        async for page in iam.get_paginator("list_user_policies").paginate(UserName=username):
            for pn in page["PolicyNames"]:
                try:
                    doc = await iam.get_user_policy(UserName=username, PolicyName=pn)
                    out.append({"PolicyName": pn, "PolicyDocument": doc["PolicyDocument"]})
                except ClientError:
                    pass
        return out

    async def _list_roles(self, iam, account_id: str) -> list[AWSPrincipal]:
        principals: list[AWSPrincipal] = []
        async for page in iam.get_paginator("list_roles").paginate():
            tasks = [self._build_role(iam, r, account_id) for r in page["Roles"]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, AWSPrincipal):
                    principals.append(r)
                else:
                    log.warning("Role build error: %s", r)
        return principals

    async def _build_role(self, iam, role: dict, account_id: str) -> AWSPrincipal:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        attached, inline = [], []
        async for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role["RoleName"]):
            attached.extend(page["AttachedPolicies"])
        async for page in iam.get_paginator("list_role_policies").paginate(RoleName=role["RoleName"]):
            for pn in page["PolicyNames"]:
                try:
                    doc = await iam.get_role_policy(RoleName=role["RoleName"], PolicyName=pn)
                    inline.append({"PolicyName": pn, "PolicyDocument": doc["PolicyDocument"]})
                except ClientError:
                    pass
        return AWSPrincipal(
            arn=role["Arn"], principal_type="Role",
            account_id=account_id, name=role["RoleName"],
            attached_policies=attached, inline_policies=inline,
            tags={t["Key"]: t["Value"] for t in role.get("Tags", [])},
            metadata={
                "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
                "max_session_duration": role.get("MaxSessionDuration"),
            },
        )

    async def _list_groups(self, iam, account_id: str) -> list[AWSPrincipal]:
        principals: list[AWSPrincipal] = []
        async for page in iam.get_paginator("list_groups").paginate():
            for g in page["Groups"]:
                attached = []
                async for p in iam.get_paginator("list_attached_group_policies").paginate(GroupName=g["GroupName"]):
                    attached.extend(p["AttachedPolicies"])
                principals.append(AWSPrincipal(
                    arn=g["Arn"], principal_type="Group",
                    account_id=account_id, name=g["GroupName"],
                    attached_policies=attached,
                ))
        return principals

    async def _list_managed_policies(self, iam) -> list[dict]:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        policies = []
        async for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for pol in page["Policies"]:
                try:
                    ver = await iam.get_policy_version(
                        PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
                    )
                    pol["Document"] = ver["PolicyVersion"]["Document"]
                except ClientError:
                    pol["Document"] = {}
                policies.append(pol)
        return policies

    async def _scan_s3(self, region: str, account_id: str) -> list[AWSResource]:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        resources: list[AWSResource] = []
        session = self._session()
        async with session.client("s3", region_name=region) as s3:
            try:
                resp = await s3.list_buckets()
                for bucket in resp.get("Buckets", []):
                    bname = bucket["Name"]
                    policy = None
                    try:
                        p = await s3.get_bucket_policy(Bucket=bname)
                        policy = json.loads(p["Policy"])
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                            log.debug("S3 policy %s: %s", bname, e)
                    resources.append(AWSResource(
                        arn=f"arn:aws:s3:::{bname}", resource_type="s3:Bucket",
                        account_id=account_id, region=region, name=bname,
                        resource_policy=policy,
                    ))
            except ClientError as e:
                log.warning("S3 error: %s", e)
        return resources

    async def _scan_lambda(self, region: str, account_id: str) -> list[AWSResource]:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        resources: list[AWSResource] = []
        session = self._session()
        async with session.client("lambda", region_name=region) as lam:
            try:
                async for page in lam.get_paginator("list_functions").paginate():
                    for fn in page["Functions"]:
                        env_vars = fn.get("Environment", {}).get("Variables", {})
                        fn_arn   = fn["FunctionArn"]
                        rp = None
                        try:
                            r = await lam.get_policy(FunctionName=fn["FunctionName"])
                            rp = json.loads(r["Policy"])
                        except ClientError:
                            pass
                        creds = _scan_for_creds(
                            json.dumps(env_vars), fn_arn,
                            "lambda:Function", account_id, region,
                        )
                        resources.append(AWSResource(
                            arn=fn_arn, resource_type="lambda:Function",
                            account_id=account_id, region=region,
                            name=fn["FunctionName"], resource_policy=rp,
                            env_vars=env_vars, discovered_creds=creds,
                            tags=fn.get("Tags", {}),
                        ))
            except ClientError as e:
                log.warning("Lambda error %s: %s", region, e)
        return resources

    async def _scan_ec2(self, region: str, account_id: str) -> list[AWSResource]:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        resources: list[AWSResource] = []
        session = self._session()
        async with session.client("ec2", region_name=region) as ec2:
            try:
                async for page in ec2.get_paginator("describe_instances").paginate():
                    for res in page["Reservations"]:
                        for inst in res["Instances"]:
                            iid = inst["InstanceId"]
                            arn = f"arn:aws:ec2:{region}:{account_id}:instance/{iid}"
                            ud  = ""
                            try:
                                r = await ec2.describe_instance_attribute(
                                    InstanceId=iid, Attribute="userData"
                                )
                                raw = r.get("UserData", {}).get("Value", "")
                                if raw:
                                    ud = base64.b64decode(raw).decode("utf-8", errors="replace")
                            except ClientError:
                                pass
                            creds = _scan_for_creds(ud, arn, "ec2:Instance", account_id, region)
                            tags  = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                            resources.append(AWSResource(
                                arn=arn, resource_type="ec2:Instance",
                                account_id=account_id, region=region,
                                name=tags.get("Name", iid),
                                env_vars={"user_data": ud[:500]},
                                discovered_creds=creds, tags=tags,
                            ))
            except ClientError as e:
                log.warning("EC2 error %s: %s", region, e)
        return resources

    async def _scan_ecs(self, region: str, account_id: str) -> list[AWSResource]:
        from botocore.exceptions import ClientError  # noqa: PLC0415
        resources: list[AWSResource] = []
        session = self._session()
        async with session.client("ecs", region_name=region) as ecs:
            try:
                async for page in ecs.get_paginator("list_task_definitions").paginate(status="ACTIVE"):
                    for td_arn in page["taskDefinitionArns"]:
                        try:
                            td  = await ecs.describe_task_definition(taskDefinition=td_arn)
                            tdd = td["taskDefinition"]
                            env_text = json.dumps(
                                [c.get("environment", [])
                                 for c in tdd.get("containerDefinitions", [])]
                            )
                            creds = _scan_for_creds(
                                env_text, td_arn, "ecs:TaskDefinition", account_id, region
                            )
                            flat: dict = {}
                            for c in tdd.get("containerDefinitions", []):
                                for ev in c.get("environment", []):
                                    flat[f"{c['name']}/{ev['name']}"] = ev["value"]
                            resources.append(AWSResource(
                                arn=td_arn, resource_type="ecs:TaskDefinition",
                                account_id=account_id, region=region,
                                name=tdd.get("family", td_arn.split("/")[-1]),
                                env_vars=flat, discovered_creds=creds,
                            ))
                        except ClientError:
                            pass
            except ClientError as e:
                log.warning("ECS error %s: %s", region, e)
        return resources

    async def _scan_region(self, region: str, account_id: str) -> list[AWSResource]:
        results = await asyncio.gather(
            self._scan_s3(region, account_id),
            self._scan_lambda(region, account_id),
            self._scan_ec2(region, account_id),
            self._scan_ecs(region, account_id),
            return_exceptions=True,
        )
        out: list[AWSResource] = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
            else:
                log.warning("Region %s error: %s", region, r)
        return out

    async def scan(self) -> AWSScanResult:
        try:
            account_id = await self.get_account_id()
        except Exception as e:
            log.error("AWS auth failed: %s", e)
            raise

        result = AWSScanResult(account_id=account_id, region=",".join(self.regions))
        log.info("AWS scan: account=%s regions=%s", account_id, self.regions)

        session = self._session()
        async with session.client("iam") as iam:
            users, roles, groups, managed = await asyncio.gather(
                self._list_users(iam, account_id),
                self._list_roles(iam, account_id),
                self._list_groups(iam, account_id),
                self._list_managed_policies(iam),
            )
        result.principals       = users + roles + groups
        result.managed_policies = managed

        region_results = await asyncio.gather(
            *[self._scan_region(r, account_id) for r in self.regions],
            return_exceptions=True,
        )
        for rr in region_results:
            if isinstance(rr, list):
                result.resources.extend(rr)

        for resource in result.resources:
            result.discovered_credentials.extend(resource.discovered_creds)

        log.info("AWS done: %d principals, %d resources, %d creds",
                 len(result.principals), len(result.resources),
                 len(result.discovered_credentials))
        return result
