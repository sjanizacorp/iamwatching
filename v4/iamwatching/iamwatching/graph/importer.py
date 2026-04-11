"""
Neo4j Graph Importer
=====================
All neo4j imports deferred inside methods.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

log = logging.getLogger(__name__)

_CONSTRAINTS = [
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


class GraphImporter:
    def __init__(self, uri: str, username: str, password: str,
                 database: str = "neo4j", scan_start_ms: int = 0):
        self.uri           = uri
        self.username      = username
        self.password      = password
        self.database      = database
        self._driver       = None
        self.scan_start_ms = scan_start_ms  # written to every node for time-scoped queries

    async def connect(self):
        import logging as _logging  # noqa: PLC0415
        from neo4j import AsyncGraphDatabase  # noqa: PLC0415

        # Silence neo4j driver's own notification logger (prints GQL warnings to stderr)
        for _noisy in ("neo4j", "neo4j.notifications", "neo4j.io"):
            _logging.getLogger(_noisy).setLevel(_logging.ERROR)

        try:
            self._driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                notifications_min_severity="OFF",
            )
        except TypeError:
            self._driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.username, self.password)
            )
        await self._driver.verify_connectivity()
        log.info("Neo4j connected: %s", self.uri)
        await self._apply_constraints()

    async def close(self):
        if self._driver:
            await self._driver.close()

    async def _run(self, query: str, parameters: Optional[dict] = None):
        async with self._driver.session(database=self.database) as session:
            result = await session.run(query, parameters or {})
            # Consume summary to absorb any GQL notifications before they
            # reach the neo4j driver's default stderr handler.
            try:
                await result.consume()
            except Exception:
                pass
            return result

    async def _apply_constraints(self):
        for c in _CONSTRAINTS:
            try:
                await self._run(c)
            except Exception as e:
                log.debug("Constraint (may exist): %s", e)

    # ── AWS ───────────────────────────────────────────────────────────────────

    async def import_aws_result(self, result) -> dict:
        stats = {"principals": 0, "resources": 0, "assume_role_edges": 0, "permissions": 0}

        for p in result.principals:
            await self._run(
                """
                MERGE (p:Principal:AWSPrincipal {arn: $arn})
                SET p.name = $name, p.principal_type = $pt,
                    p.account_id = $account_id, p.tags = $tags,
                    p.metadata = $metadata,
                    p.attached_policy_count = $apc,
                    p.inline_policy_count = $ipc,
                    p.attached_policies = $ap_json,
                    p.inline_policies = $ip_json,
                    p.updated_at = timestamp(),
                    p.scan_start_ms = $ssm
                """,
                {"arn": p.arn, "name": p.name, "pt": p.principal_type,
                 "account_id": p.account_id, "tags": json.dumps(p.tags),
                 "metadata": json.dumps(p.metadata),
                 "apc": len(p.attached_policies),
                 "ipc": len(p.inline_policies),
                 "ap_json": json.dumps(p.attached_policies),
                 "ip_json": json.dumps(p.inline_policies),
                 "ssm": self.scan_start_ms},
            )
            stats["principals"] += 1

            if p.principal_type == "Role":
                for stmt in p.metadata.get("assume_role_policy", {}).get("Statement", []):
                    aws_list = stmt.get("Principal", {}).get("AWS", [])
                    if isinstance(aws_list, str):
                        aws_list = [aws_list]
                    for src in aws_list:
                        try:
                            await self._run(
                                """
                                MERGE (src:Principal:AWSPrincipal {arn: $src})
                                MERGE (tgt:Principal:AWSPrincipal {arn: $tgt})
                                MERGE (src)-[e:CAN_ASSUME]->(tgt)
                                SET e.condition = $cond, e.updated_at = timestamp()
                                """,
                                {"src": src, "tgt": p.arn,
                                 "cond": json.dumps(stmt.get("Condition", {}))},
                            )
                            stats["assume_role_edges"] += 1
                        except Exception:
                            pass

        for r in result.resources:
            await self._run(
                """
                MERGE (r:Resource:AWSResource {arn: $arn})
                SET r.name = $name, r.resource_type = $rt,
                    r.account_id = $account_id, r.region = $region,
                    r.tags = $tags, r.has_env_vars = $hev,
                    r.encrypted = $encrypted,
                    r.public_access = $public_access,
                    r.logging_enabled = $logging_enabled,
                    r.backup_enabled = $backup_enabled,
                    r.versioning_enabled = $versioning_enabled,
                    r.deletion_protection = $deletion_protection,
                    r.multi_az = $multi_az,
                    r.auth_type = $auth_type,
                    r.tls_policy = $tls_policy,
                    r.vpc_id = $vpc_id,
                    r.port = $port,
                    r.metadata = $metadata,
                    r.updated_at = timestamp(),
                    r.scan_start_ms = $ssm
                """,
                {"arn": r.arn, "name": r.name, "rt": r.resource_type,
                 "account_id": r.account_id, "region": r.region,
                 "tags": json.dumps(r.tags), "hev": bool(r.env_vars),
                 "encrypted":           getattr(r, "encrypted",           False),
                 "public_access":       getattr(r, "public_access",       False),
                 "logging_enabled":     getattr(r, "logging_enabled",     False),
                 "backup_enabled":      getattr(r, "backup_enabled",      False),
                 "versioning_enabled":  getattr(r, "versioning_enabled",  False),
                 "deletion_protection": getattr(r, "deletion_protection",  False),
                 "multi_az":            getattr(r, "multi_az",            False),
                 "auth_type":           getattr(r, "auth_type",           ""),
                 "tls_policy":          getattr(r, "tls_policy",          ""),
                 "vpc_id":              getattr(r, "vpc_id",              ""),
                 "port":                getattr(r, "port",                0),
                 "metadata":            json.dumps(getattr(r, "metadata", {})),
                 "ssm":                 self.scan_start_ms},
            )
            stats["resources"] += 1

            if r.resource_policy:
                for stmt in r.resource_policy.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principals = stmt.get("Principal", {})
                    aws_list   = (principals if isinstance(principals, list)
                                  else principals.get("AWS", []))
                    if isinstance(aws_list, str):
                        aws_list = [aws_list]
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for pa in aws_list:
                        for action in actions:
                            try:
                                await self._run(
                                    """
                                    MERGE (p:Principal:AWSPrincipal {arn: $pa})
                                    MERGE (r:Resource:AWSResource {arn: $arn})
                                    MERGE (p)-[e:HAS_PERMISSION {action: $action, resource_id: $arn}]->(r)
                                    SET e.effect = 'Allow', e.condition = $cond,
                                        e.updated_at = timestamp()
                                    """,
                                    {"pa": pa, "arn": r.arn, "action": action,
                                     "cond": json.dumps(stmt.get("Condition", {}))},
                                )
                                stats["permissions"] += 1
                            except Exception:
                                pass
        return stats

    # ── Azure ─────────────────────────────────────────────────────────────────

    async def import_azure_result(self, result) -> dict:
        stats = {"principals": 0, "resources": 0, "role_assignments": 0}

        for p in result.principals:
            await self._run(
                """
                MERGE (p:Principal:AzurePrincipal {object_id: $oid})
                SET p.display_name = $dn, p.principal_type = $pt,
                    p.upn = $upn, p.app_id = $app_id,
                    p.subscription_id = $sub, p.updated_at = timestamp(),
                    p.scan_start_ms = $ssm
                """,
                {"oid": p.object_id, "dn": p.display_name, "pt": p.principal_type,
                 "upn": p.upn or "", "app_id": p.app_id or "",
                 "sub": result.subscription_id, "ssm": self.scan_start_ms},
            )
            stats["principals"] += 1

            for ra in p.role_assignments:
                rd_id = ra.get("role_definition_id", "")
                try:
                    await self._run(
                        "MERGE (rd:RoleDefinition {role_id: $rid}) SET rd.scope = $scope",
                        {"rid": rd_id, "scope": ra.get("scope", "")},
                    )
                    await self._run(
                        """
                        MATCH (p:AzurePrincipal {object_id: $oid})
                        MATCH (rd:RoleDefinition {role_id: $rid})
                        MERGE (p)-[e:ASSIGNED_ROLE]->(rd)
                        SET e.scope = $scope, e.condition = $cond,
                            e.updated_at = timestamp()
                        """,
                        {"oid": p.object_id, "rid": rd_id,
                         "scope": ra.get("scope", ""),
                         "cond": ra.get("condition") or ""},
                    )
                    stats["role_assignments"] += 1
                except Exception:
                    pass

        for r in result.resources:
            await self._run(
                """
                MERGE (r:Resource:AzureResource {resource_id: $rid})
                SET r.name = $name, r.resource_type = $rt,
                    r.subscription_id = $sub, r.resource_group = $rg,
                    r.location = $loc, r.has_env_vars = $hev,
                    r.updated_at = timestamp(),
                    r.scan_start_ms = $ssm
                """,
                {"rid": r.resource_id, "name": r.name, "rt": r.resource_type,
                 "sub": r.subscription_id, "rg": r.resource_group,
                 "loc": r.location, "hev": bool(r.env_vars),
                 "ssm": self.scan_start_ms},
            )
            stats["resources"] += 1
        return stats

    # ── GCP ───────────────────────────────────────────────────────────────────

    async def import_gcp_result(self, result) -> dict:
        stats = {"principals": 0, "resources": 0, "bindings": 0, "keys": 0}

        for p in result.principals:
            await self._run(
                """
                MERGE (p:Principal:GCPPrincipal {email: $email})
                SET p.display_name = $dn, p.principal_type = $pt,
                    p.project_id = $pid, p.updated_at = timestamp(),
                    p.scan_start_ms = $ssm
                """,
                {"email": p.email, "dn": p.display_name,
                 "pt": p.principal_type, "pid": p.project_id,
                 "ssm": self.scan_start_ms},
            )
            stats["principals"] += 1

            for key in p.keys:
                try:
                    await self._run(
                        """
                        MATCH (sa:GCPPrincipal {email: $email})
                        MERGE (k:SAKey {key_id: $kid})
                        SET k.key_type = $kt, k.valid_after = $va, k.valid_before = $vb
                        MERGE (sa)-[:HAS_KEY]->(k)
                        """,
                        {"email": p.email,
                         "kid": key.get("name", "").split("/")[-1],
                         "kt": key.get("keyType", ""),
                         "va": str(key.get("validAfterTime", "")),
                         "vb": str(key.get("validBeforeTime", ""))},
                    )
                    stats["keys"] += 1
                except Exception:
                    pass

            for binding in p.iam_bindings:
                rid = binding["resource"]
                try:
                    await self._run(
                        """
                        MERGE (res:GCPResource {resource_id: $rid})
                        SET res.resource_type = 'cloudresourcemanager/Project'
                        """,
                        {"rid": rid},
                    )
                    await self._run(
                        """
                        MATCH (p:GCPPrincipal {email: $email})
                        MATCH (r:GCPResource {resource_id: $rid})
                        MERGE (p)-[e:HAS_BINDING {role: $role}]->(r)
                        SET e.updated_at = timestamp()
                        """,
                        {"email": p.email, "rid": rid, "role": binding["role"]},
                    )
                    stats["bindings"] += 1
                except Exception:
                    pass

        for r in result.resources:
            await self._run(
                """
                MERGE (r:Resource:GCPResource {resource_id: $rid})
                SET r.name = $name, r.resource_type = $rt,
                    r.project_id = $pid, r.location = $loc,
                    r.has_env_vars = $hev, r.updated_at = timestamp(),
                    r.scan_start_ms = $ssm
                """,
                {"rid": r.resource_id, "name": r.name, "rt": r.resource_type,
                 "pid": r.project_id, "loc": r.location, "hev": bool(r.env_vars),
                 "ssm": self.scan_start_ms},
            )
            stats["resources"] += 1
        return stats

    # ── Verification links ────────────────────────────────────────────────────

    async def import_verification_results(self, verification_results: list) -> dict:
        stats = {"cross_cloud_links": 0, "verified": 0}
        for vr in verification_results:
            if not vr.identity:
                continue
            try:
                await self._run(
                    """
                    MATCH (src) WHERE src.arn = $src OR src.resource_id = $src
                    MERGE (tgt:Principal {identity_hint: $identity})
                    MERGE (src)-[e:CROSS_CLOUD_LINK]->(tgt)
                    SET e.cred_type = $ct, e.status = $st,
                        e.target_cloud = $tc, e.source_cloud = $sc,
                        e.verified = $v, e.account = $acct,
                        e.updated_at = timestamp()
                    """,
                    {"src": vr.credential_source_resource,
                     "identity": vr.identity or "",
                     "ct": vr.credential_type, "st": str(vr.status),
                     "tc": vr.target_cloud, "sc": vr.credential_source_cloud,
                     "v": vr.verified_link, "acct": vr.account or ""},
                )
                stats["cross_cloud_links"] += 1
                if vr.verified_link:
                    stats["verified"] += 1
            except Exception as e:
                log.debug("Cross-cloud link error: %s", e)
        return stats

    async def import_all(
        self, aws_result=None, azure_result=None, gcp_result=None,
        verification_results=None,
    ) -> dict:
        all_stats: dict = {}
        if aws_result:
            all_stats["aws"]   = await self.import_aws_result(aws_result)
        if azure_result:
            all_stats["azure"] = await self.import_azure_result(azure_result)
        if gcp_result:
            all_stats["gcp"]   = await self.import_gcp_result(gcp_result)
        if verification_results:
            all_stats["verification"] = await self.import_verification_results(verification_results)
        log.info("Graph import complete: %s", all_stats)
        return all_stats
