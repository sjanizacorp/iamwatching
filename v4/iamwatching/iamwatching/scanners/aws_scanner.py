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
    resource_policy:    Optional[dict] = None
    env_vars:           dict  = field(default_factory=dict)
    discovered_creds:   list  = field(default_factory=list)
    tags:               dict  = field(default_factory=dict)
    # Security-relevant metadata stored as flat properties for Cypher queries
    encrypted:          bool  = False   # encryption at rest
    public_access:      bool  = False   # publicly accessible
    logging_enabled:    bool  = False   # audit/access logging
    backup_enabled:     bool  = False   # backup / PITR enabled
    versioning_enabled: bool  = False   # S3 versioning, etc.
    deletion_protection:bool  = False   # deletion protection
    multi_az:           bool  = False   # multi-AZ / HA
    auth_type:          str   = ""      # none / iam / key / cert
    tls_policy:         str   = ""      # min TLS version
    vpc_id:             str   = ""      # VPC if isolated
    port:               int   = 0       # service port


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

    # ── EKS ──────────────────────────────────────────────────────────────────

    async def _scan_eks(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("eks", region_name=region) as eks:
                paginator = eks.get_paginator("list_clusters")
                cluster_names: list[str] = []
                async for page in paginator.paginate():
                    cluster_names.extend(page.get("clusters", []))
                for name in cluster_names:
                    try:
                        c = (await eks.describe_cluster(name=name))["cluster"]
                        logging_cfg = c.get("logging", {}).get("clusterLogging", [])
                        logging_on = any(
                            t.get("enabled") for t in logging_cfg
                        )
                        resources.append(AWSResource(
                            arn=c["arn"],
                            resource_type="eks:Cluster",
                            account_id=account_id,
                            region=region,
                            name=name,
                            encrypted=bool(c.get("encryptionConfig")),
                            logging_enabled=logging_on,
                            public_access=c.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True),
                            vpc_id=c.get("resourcesVpcConfig", {}).get("vpcId", ""),
                            auth_type=c.get("accessConfig", {}).get("authenticationMode", ""),
                            tags=c.get("tags", {}),
                            metadata={
                                "version": c.get("version", ""),
                                "status": c.get("status", ""),
                                "role_arn": c.get("roleArn", ""),
                                "endpoint_private": c.get("resourcesVpcConfig", {}).get("endpointPrivateAccess", False),
                                "endpoint_public": c.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True),
                                "public_cidrs": c.get("resourcesVpcConfig", {}).get("publicAccessCidrs", []),
                            },
                        ))
                    except Exception:
                        pass
        except Exception:
            pass
        return resources

    # ── RDS ───────────────────────────────────────────────────────────────────

    async def _scan_rds(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("rds", region_name=region) as rds:
                paginator = rds.get_paginator("describe_db_instances")
                async for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        arn = db.get("DBInstanceArn", "")
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="rds:DBInstance",
                            account_id=account_id,
                            region=region,
                            name=db.get("DBInstanceIdentifier", ""),
                            encrypted=db.get("StorageEncrypted", False),
                            public_access=db.get("PubliclyAccessible", False),
                            multi_az=db.get("MultiAZ", False),
                            deletion_protection=db.get("DeletionProtection", False),
                            backup_enabled=db.get("BackupRetentionPeriod", 0) > 0,
                            port=db.get("Endpoint", {}).get("Port", 0),
                            vpc_id=db.get("DBSubnetGroup", {}).get("VpcId", ""),
                            tls_policy=db.get("PendingModifiedValues", {}).get("CACertificateIdentifier", ""),
                            tags={t["Key"]: t["Value"] for t in db.get("TagList", [])},
                            metadata={
                                "engine": db.get("Engine", ""),
                                "engine_version": db.get("EngineVersion", ""),
                                "instance_class": db.get("DBInstanceClass", ""),
                                "status": db.get("DBInstanceStatus", ""),
                                "ca_cert": db.get("CACertificateIdentifier", ""),
                                "iam_auth": db.get("IAMDatabaseAuthenticationEnabled", False),
                                "auto_minor_upgrade": db.get("AutoMinorVersionUpgrade", False),
                                "performance_insights": db.get("PerformanceInsightsEnabled", False),
                                "monitoring_interval": db.get("MonitoringInterval", 0),
                            },
                        ))
        except Exception:
            pass
        return resources

    # ── DynamoDB ──────────────────────────────────────────────────────────────

    async def _scan_dynamodb(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("dynamodb", region_name=region) as ddb:
                paginator = ddb.get_paginator("list_tables")
                async for page in paginator.paginate():
                    for table_name in page.get("TableNames", []):
                        try:
                            t = (await ddb.describe_table(TableName=table_name))["Table"]
                            pitr = False
                            try:
                                pitr_resp = await ddb.describe_continuous_backups(TableName=table_name)
                                pitr = pitr_resp.get("ContinuousBackupsDescription", {}).get(
                                    "PointInTimeRecoveryDescription", {}).get(
                                    "PointInTimeRecoveryStatus") == "ENABLED"
                            except Exception:
                                pass
                            arn = t.get("TableArn", f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}")
                            enc = t.get("SSEDescription", {})
                            resources.append(AWSResource(
                                arn=arn,
                                resource_type="dynamodb:Table",
                                account_id=account_id,
                                region=region,
                                name=table_name,
                                encrypted=enc.get("Status") == "ENABLED",
                                backup_enabled=pitr,
                                tags={},
                                metadata={
                                    "status": t.get("TableStatus", ""),
                                    "billing_mode": t.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                                    "item_count": t.get("ItemCount", 0),
                                    "size_bytes": t.get("TableSizeBytes", 0),
                                    "streams_enabled": bool(t.get("StreamSpecification")),
                                    "deletion_protection": t.get("DeletionProtectionEnabled", False),
                                },
                            ))
                        except Exception:
                            pass
        except Exception:
            pass
        return resources

    # ── API Gateway ───────────────────────────────────────────────────────────

    async def _scan_apigateway(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            # REST APIs (v1)
            async with session.client("apigateway", region_name=region) as apigw:
                try:
                    resp = await apigw.get_rest_apis(limit=500)
                    for api in resp.get("items", []):
                        api_id = api.get("id", "")
                        arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="apigateway:RestApi",
                            account_id=account_id,
                            region=region,
                            name=api.get("name", api_id),
                            tls_policy=api.get("minimumCompressionSize", ""),
                            tags=api.get("tags", {}),
                            metadata={
                                "endpoint_type": api.get("endpointConfiguration", {}).get("types", []),
                                "policy": bool(api.get("policy")),
                                "disable_execute_api": api.get("disableExecuteApiEndpoint", False),
                                "api_key_source": api.get("apiKeySource", "HEADER"),
                            },
                        ))
                except Exception:
                    pass
            # HTTP/WebSocket APIs (v2)
            async with session.client("apigatewayv2", region_name=region) as apigw2:
                try:
                    resp = await apigw2.get_apis()
                    for api in resp.get("Items", []):
                        api_id = api.get("ApiId", "")
                        arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="apigateway:HttpApi",
                            account_id=account_id,
                            region=region,
                            name=api.get("Name", api_id),
                            tags=api.get("Tags", {}),
                            metadata={
                                "protocol": api.get("ProtocolType", ""),
                                "cors_config": bool(api.get("CorsConfiguration")),
                                "disable_execute_api": api.get("DisableExecuteApiEndpoint", False),
                            },
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return resources

    # ── SQS ───────────────────────────────────────────────────────────────────

    async def _scan_sqs(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("sqs", region_name=region) as sqs:
                resp = await sqs.list_queues()
                urls = resp.get("QueueUrls", [])
                for url in urls:
                    try:
                        attrs = (await sqs.get_queue_attributes(
                            QueueUrl=url,
                            AttributeNames=["All"],
                        )).get("Attributes", {})
                        arn = attrs.get("QueueArn", "")
                        name = url.split("/")[-1]
                        policy = attrs.get("Policy", "")
                        is_public = False
                        if policy:
                            import json as _json
                            try:
                                doc = _json.loads(policy)
                                is_public = any(
                                    s.get("Principal") in ("*", {"AWS": "*"})
                                    for s in doc.get("Statement", [])
                                    if s.get("Effect") == "Allow"
                                )
                            except Exception:
                                pass
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="sqs:Queue",
                            account_id=account_id,
                            region=region,
                            name=name,
                            encrypted=bool(attrs.get("SqsManagedSseEnabled") == "true" or attrs.get("KmsMasterKeyId")),
                            public_access=is_public,
                            metadata={
                                "visibility_timeout": attrs.get("VisibilityTimeout", "30"),
                                "message_retention": attrs.get("MessageRetentionPeriod", ""),
                                "kms_key": attrs.get("KmsMasterKeyId", ""),
                                "dlq": bool(attrs.get("RedrivePolicy")),
                                "fifo": name.endswith(".fifo"),
                            },
                        ))
                    except Exception:
                        pass
        except Exception:
            pass
        return resources

    # ── ElastiCache ───────────────────────────────────────────────────────────

    async def _scan_elasticache(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("elasticache", region_name=region) as ec:
                paginator = ec.get_paginator("describe_cache_clusters")
                async for page in paginator.paginate(ShowCacheNodeInfo=False):
                    for cluster in page.get("CacheClusters", []):
                        cid = cluster.get("CacheClusterId", "")
                        arn = f"arn:aws:elasticache:{region}:{account_id}:cluster:{cid}"
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="elasticache:Cluster",
                            account_id=account_id,
                            region=region,
                            name=cid,
                            encrypted=cluster.get("AtRestEncryptionEnabled", False),
                            auth_type="token" if cluster.get("AuthTokenEnabled", False) else "none",
                            metadata={
                                "engine": cluster.get("Engine", ""),
                                "engine_version": cluster.get("EngineVersion", ""),
                                "status": cluster.get("CacheClusterStatus", ""),
                                "node_type": cluster.get("CacheNodeType", ""),
                                "transit_encryption": cluster.get("TransitEncryptionEnabled", False),
                                "auth_token": cluster.get("AuthTokenEnabled", False),
                                "auto_minor_upgrade": cluster.get("AutoMinorVersionUpgrade", False),
                                "num_nodes": cluster.get("NumCacheNodes", 1),
                                "replication_group": cluster.get("ReplicationGroupId", ""),
                            },
                        ))
        except Exception:
            pass
        return resources

    # ── Redshift ──────────────────────────────────────────────────────────────

    async def _scan_redshift(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("redshift", region_name=region) as rs:
                paginator = rs.get_paginator("describe_clusters")
                async for page in paginator.paginate():
                    for cluster in page.get("Clusters", []):
                        cid = cluster.get("ClusterIdentifier", "")
                        arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cid}"
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="redshift:Cluster",
                            account_id=account_id,
                            region=region,
                            name=cid,
                            encrypted=cluster.get("Encrypted", False),
                            public_access=cluster.get("PubliclyAccessible", False),
                            logging_enabled=cluster.get("LoggingStatus", {}).get("LoggingEnabled", False),
                            multi_az=cluster.get("MultiAZ", "Disabled") != "Disabled",
                            vpc_id=cluster.get("VpcId", ""),
                            port=cluster.get("Endpoint", {}).get("Port", 5439),
                            tags={t["Key"]: t["Value"] for t in cluster.get("Tags", [])},
                            metadata={
                                "status": cluster.get("ClusterStatus", ""),
                                "node_type": cluster.get("NodeType", ""),
                                "num_nodes": cluster.get("NumberOfNodes", 1),
                                "iam_roles": [r.get("IamRoleArn") for r in cluster.get("IamRoles", [])],
                                "enhanced_vpc_routing": cluster.get("EnhancedVpcRouting", False),
                                "require_ssl": cluster.get("PendingModifiedValues", {}).get("EnhancedVpcRouting", False),
                                "auto_snapshot": cluster.get("AutomatedSnapshotRetentionPeriod", 1) > 0,
                                "maintenance_window": cluster.get("PreferredMaintenanceWindow", ""),
                            },
                        ))
        except Exception:
            pass
        return resources

    # ── Kinesis ───────────────────────────────────────────────────────────────

    async def _scan_kinesis(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("kinesis", region_name=region) as kin:
                paginator = kin.get_paginator("list_streams")
                async for page in paginator.paginate():
                    for name in page.get("StreamNames", []):
                        try:
                            s = (await kin.describe_stream_summary(StreamName=name)).get("StreamDescriptionSummary", {})
                            arn = s.get("StreamARN", f"arn:aws:kinesis:{region}:{account_id}:stream/{name}")
                            resources.append(AWSResource(
                                arn=arn,
                                resource_type="kinesis:Stream",
                                account_id=account_id,
                                region=region,
                                name=name,
                                encrypted=s.get("EncryptionType", "NONE") != "NONE",
                                metadata={
                                    "status": s.get("StreamStatus", ""),
                                    "shard_count": s.get("OpenShardCount", 0),
                                    "retention_hours": s.get("RetentionPeriodHours", 24),
                                    "encryption_type": s.get("EncryptionType", "NONE"),
                                    "kms_key": s.get("KeyId", ""),
                                    "enhanced_monitoring": [
                                        m.get("ShardLevelMetrics", [])
                                        for m in s.get("EnhancedMonitoring", [])
                                    ],
                                },
                            ))
                        except Exception:
                            pass
        except Exception:
            pass
        return resources

    # ── CloudFront ────────────────────────────────────────────────────────────

    async def _scan_cloudfront(self, account_id: str) -> list[AWSResource]:
        """CloudFront is global — no region parameter needed."""
        resources: list[AWSResource] = []
        try:
            session = self._session()
            # CloudFront is always in us-east-1
            async with session.client("cloudfront", region_name="us-east-1") as cf:
                paginator = cf.get_paginator("list_distributions")
                async for page in paginator.paginate():
                    dist_list = page.get("DistributionList", {})
                    for dist in dist_list.get("Items", []):
                        did = dist.get("Id", "")
                        arn = dist.get("ARN", f"arn:aws:cloudfront::{account_id}:distribution/{did}")
                        origins = dist.get("Origins", {}).get("Items", [])
                        http_only = any(
                            o.get("CustomOriginConfig", {}).get("OriginProtocolPolicy") == "http-only"
                            for o in origins
                        )
                        viewer_cert = dist.get("ViewerCertificate", {})
                        tls_version = viewer_cert.get("MinimumProtocolVersion", "")
                        has_waf = bool(dist.get("WebACLId"))
                        default_cache = dist.get("DefaultCacheBehavior", {})
                        https_redirect = default_cache.get("ViewerProtocolPolicy") in (
                            "redirect-to-https", "https-only"
                        )
                        resources.append(AWSResource(
                            arn=arn,
                            resource_type="cloudfront:Distribution",
                            account_id=account_id,
                            region="global",
                            name=dist.get("DomainName", did),
                            encrypted=https_redirect and not http_only,
                            tls_policy=tls_version,
                            tags={},
                            metadata={
                                "status": dist.get("Status", ""),
                                "enabled": dist.get("Enabled", True),
                                "https_redirect": https_redirect,
                                "http_only_origin": http_only,
                                "tls_min_version": tls_version,
                                "waf_enabled": has_waf,
                                "geo_restriction": dist.get("Restrictions", {}).get(
                                    "GeoRestriction", {}).get("RestrictionType", "none"),
                                "price_class": dist.get("PriceClass", ""),
                                "aliases": dist.get("Aliases", {}).get("Items", []),
                                "logging": bool(dist.get("Logging", {}).get("Enabled")),
                            },
                        ))
        except Exception:
            pass
        return resources

    # ── SNS ───────────────────────────────────────────────────────────────────

    async def _scan_sns(self, region: str, account_id: str) -> list[AWSResource]:
        resources: list[AWSResource] = []
        try:
            session = self._session()
            async with session.client("sns", region_name=region) as sns:
                paginator = sns.get_paginator("list_topics")
                async for page in paginator.paginate():
                    for topic in page.get("Topics", []):
                        arn = topic.get("TopicArn", "")
                        name = arn.split(":")[-1] if arn else ""
                        try:
                            attrs = (await sns.get_topic_attributes(TopicArn=arn)).get("Attributes", {})
                            policy_str = attrs.get("Policy", "")
                            is_public = False
                            if policy_str:
                                import json as _json
                                try:
                                    doc = _json.loads(policy_str)
                                    is_public = any(
                                        s.get("Principal") in ("*", {"AWS": "*"})
                                        for s in doc.get("Statement", [])
                                        if s.get("Effect") == "Allow"
                                    )
                                except Exception:
                                    pass
                            resources.append(AWSResource(
                                arn=arn,
                                resource_type="sns:Topic",
                                account_id=account_id,
                                region=region,
                                name=name,
                                encrypted=bool(attrs.get("KmsMasterKeyId")),
                                public_access=is_public,
                                metadata={
                                    "kms_key": attrs.get("KmsMasterKeyId", ""),
                                    "subscriptions_confirmed": attrs.get("SubscriptionsConfirmed", "0"),
                                    "fifo": name.endswith(".fifo"),
                                    "content_based_dedup": attrs.get("ContentBasedDeduplication", "false"),
                                },
                            ))
                        except Exception:
                            pass
        except Exception:
            pass
        return resources

    async def _scan_region(self, region: str, account_id: str) -> list[AWSResource]:
        results = await asyncio.gather(
            self._scan_s3(region, account_id),
            self._scan_lambda(region, account_id),
            self._scan_ec2(region, account_id),
            self._scan_ecs(region, account_id),
            self._scan_eks(region, account_id),
            self._scan_rds(region, account_id),
            self._scan_dynamodb(region, account_id),
            self._scan_apigateway(region, account_id),
            self._scan_sqs(region, account_id),
            self._scan_sns(region, account_id),
            self._scan_elasticache(region, account_id),
            self._scan_redshift(region, account_id),
            self._scan_kinesis(region, account_id),
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

        # CloudFront is global — scan once, not per-region
        cf_resources = await self._scan_cloudfront(account_id)
        result.resources.extend(cf_resources)

        for resource in result.resources:
            result.discovered_credentials.extend(resource.discovered_creds)

        log.info("AWS done: %d principals, %d resources, %d creds",
                 len(result.principals), len(result.resources),
                 len(result.discovered_credentials))
        return result
