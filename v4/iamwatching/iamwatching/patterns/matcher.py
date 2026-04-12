"""
Pattern Matcher
===============
Cypher-based detection of dangerous IAM patterns including:
  - Shadow Admin privilege escalation (AWS/Azure/GCP)
  - Cross-cloud verified credential paths
  - Wildcard permission grants
  - Publicly accessible resources
  - Service account key exposure
  - Overprivileged compute identities
  - iam:PassRole abuse chains
  - Azure Role Assignment write paths
  - GCP Service Account impersonation chains
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# neo4j imported lazily inside connect()

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    affected_nodes: list[dict] = field(default_factory=list)
    recommendation: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    raw_records: list[dict] = field(default_factory=list)
    not_evaluated: bool = False
    not_evaluated_reason: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Detection Rules
# Each rule is: (rule_id, title, severity, description, cypher, recommendation, mitre)
# ─────────────────────────────────────────────────────────────────────────────

RULES = [

    # ── AWS Shadow Admin: iam:PassRole ────────────────────────────────────────
    (
        "AWS-001",
        "Shadow Admin via iam:PassRole",
        Severity.CRITICAL,
        """
        A principal has iam:PassRole permission, which allows it to pass a higher-privileged
        role to an AWS service. This is a classic privilege escalation path: the principal
        does not need AdministratorAccess itself; it can attach an admin role to a Lambda,
        EC2 instance, or other service it controls, achieving effective admin access.
        """,
        """
        MATCH (p:AWSPrincipal)-[e:HAS_PERMISSION]->(r)
        WHERE e.action IN ['iam:PassRole', 'iam:*', '*']
        WITH p, collect({action: e.action, resource: r.arn}) AS perms
        MATCH (p)-[:CAN_ASSUME]->(admin_role:AWSPrincipal)
        WHERE admin_role.name CONTAINS 'Admin' OR admin_role.name CONTAINS 'admin'
        RETURN p.arn AS principal, p.principal_type AS type,
               perms AS passrole_permissions,
               collect(admin_role.arn) AS reachable_admin_roles
        LIMIT 50
        """,
        "Remove iam:PassRole from non-service principals. Use resource-level conditions "
        "to restrict which roles can be passed. Audit all roles passable by this principal.",
        ["T1078.004 - Cloud Accounts", "T1098.001 - Additional Cloud Credentials"],
    ),

    # ── AWS Shadow Admin: CreatePolicyVersion ─────────────────────────────────
    (
        "AWS-002",
        "Shadow Admin via iam:CreatePolicyVersion",
        Severity.CRITICAL,
        """
        A principal can create new versions of managed policies. By creating a new policy
        version with AdministratorAccess and setting it as the default, the principal
        effectively escalates to admin across all entities that have the policy attached.
        """,
        """
        MATCH (p:AWSPrincipal)-[e:HAS_PERMISSION]->(r)
        WHERE e.action IN ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:*', '*']
        WITH p, collect(e.action) AS dangerous_actions
        WHERE size(dangerous_actions) >= 1
        RETURN p.arn AS principal, p.principal_type AS type,
               dangerous_actions,
               'Can rewrite managed policies to gain admin' AS escalation_path
        LIMIT 50
        """,
        "Restrict iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion. Require MFA "
        "for sensitive IAM operations. Use SCPs to deny these for non-break-glass accounts.",
        ["T1078.004 - Cloud Accounts", "T1484 - Domain Policy Modification"],
    ),

    # ── AWS: Wildcard Resource on Sensitive Actions ───────────────────────────
    (
        "AWS-003",
        "Wildcard (*) Resource on Sensitive IAM Actions",
        Severity.HIGH,
        """
        A principal has sensitive IAM or STS actions scoped to all resources (*).
        This indicates an overly broad permission grant that violates least-privilege.
        """,
        """
        MATCH (p:AWSPrincipal)-[e:HAS_PERMISSION]->(r)
        WHERE (e.action STARTS WITH 'iam:' OR e.action STARTS WITH 'sts:' OR e.action = '*')
          AND (r.arn ENDS WITH ':*' OR e.resource_id = '*' OR r.arn CONTAINS '/*')
        RETURN p.arn AS principal, p.principal_type AS type,
               collect(DISTINCT e.action) AS wildcard_actions,
               count(e) AS permission_count
        ORDER BY permission_count DESC
        LIMIT 50
        """,
        "Scope all IAM actions to specific resource ARNs. Replace wildcard resources "
        "with explicit ARNs using IAM condition keys (aws:ResourceTag, arn conditions).",
        ["T1078.004 - Cloud Accounts"],
    ),

    # ── AWS: Assume Role Cross-Account Without External ID ────────────────────
    (
        "AWS-004",
        "Cross-Account Role Trust Without External ID Condition",
        Severity.HIGH,
        """
        A role trust policy allows cross-account assumption without an ExternalId condition.
        This enables the 'confused deputy' attack where any principal in the trusted account
        can assume the role without additional verification.
        """,
        """
        MATCH (src:AWSPrincipal)-[e:CAN_ASSUME]->(tgt:AWSPrincipal)
        WHERE src.account_id <> tgt.account_id
          AND NOT e.condition CONTAINS 'ExternalId'
          AND NOT e.condition CONTAINS 'sts:ExternalId'
        RETURN src.arn AS trusting_principal,
               tgt.arn AS trusted_role,
               tgt.account_id AS role_account,
               e.condition AS trust_condition
        LIMIT 50
        """,
        "Add sts:ExternalId condition to all cross-account trust policies. "
        "Use aws:PrincipalOrgID to restrict to your organization.",
        ["T1199 - Trusted Relationship", "T1078.004 - Cloud Accounts"],
    ),

    # ── AWS: Compute Resource with Cross-Cloud Credentials ───────────────────
    (
        "AWS-005",
        "Verified Cross-Cloud Credential in AWS Compute",
        Severity.CRITICAL,
        """
        A live, verified cross-cloud credential (Azure SP secret, GCP SA key) was found
        in an AWS compute resource's environment variables or startup script. This is a
        confirmed cross-cloud lateral movement path.
        """,
        """
        MATCH (r:AWSResource)-[e:CROSS_CLOUD_LINK {verified: true}]->(tgt)
        RETURN r.arn AS source_resource,
               r.resource_type AS resource_type,
               e.cred_type AS credential_type,
               e.target_cloud AS target_cloud,
               tgt.identity_hint AS target_identity,
               e.account AS target_account
        ORDER BY e.target_cloud, r.resource_type
        LIMIT 50
        """,
        "Immediately rotate the exposed credentials. Migrate secrets to AWS Secrets Manager "
        "or Parameter Store with KMS encryption. Audit what the leaked credential could access.",
        ["T1552.001 - Credentials In Files", "T1552.005 - Cloud Instance Metadata API"],
    ),

    # ── AWS: Lambda with Admin Role ───────────────────────────────────────────
    (
        "AWS-006",
        "Lambda Function Executing with Admin-Equivalent Role",
        Severity.HIGH,
        """
        A Lambda function has an execution role that carries admin-level permissions.
        Since Lambda functions are often internet-reachable and accept arbitrary input,
        a compromise of the function yields admin-level cloud access.
        """,
        """
        MATCH (p:AWSPrincipal {principal_type: 'Role'})-[e:HAS_PERMISSION]->(r)
        WHERE e.action IN ['*', 'iam:*', 's3:*']
        WITH p, collect(e.action) AS admin_actions
        MATCH (fn:AWSResource {resource_type: 'lambda:Function'})-[:DEPLOYED_WITH_ROLE]->(p)
        RETURN fn.arn AS lambda_function,
               p.arn AS execution_role,
               admin_actions
        LIMIT 50
        """,
        "Apply least-privilege to all Lambda execution roles. Grant only the specific "
        "actions and resources the function needs. Use separate roles per function.",
        ["T1078.004 - Cloud Accounts", "T1610 - Deploy Container"],
    ),

    # ── Azure: Role Assignment Write (Shadow Admin) ───────────────────────────
    (
        "AZ-001",
        "Shadow Admin via Azure Role Assignment Write",
        Severity.CRITICAL,
        """
        A principal (user, group, or service principal) has been assigned a role that
        includes Microsoft.Authorization/roleAssignments/write. This allows the principal
        to grant itself or any other identity any role in the scope, effectively achieving
        Owner-level access without being assigned Owner directly.
        """,
        """
        MATCH (p:AzurePrincipal)-[:ASSIGNED_ROLE]->(rd:RoleDefinition)
        WHERE rd.role_id CONTAINS 'Owner'
           OR rd.role_id CONTAINS 'UserAccessAdministrator'
        WITH p, collect(rd) AS dangerous_roles
        RETURN p.object_id AS principal_id,
               p.display_name AS name,
               p.principal_type AS type,
               [r IN dangerous_roles | r.role_id] AS roles_with_assignment_write
        LIMIT 50
        """,
        "Remove Microsoft.Authorization/roleAssignments/write from non-Owner roles. "
        "Use Azure PIM (Privileged Identity Management) with approval workflows for "
        "role assignment capabilities. Audit all custom role definitions.",
        ["T1078.004 - Cloud Accounts", "T1484 - Domain Policy Modification"],
    ),

    # ── Azure: Service Principal with Client Secret in Function App ───────────
    (
        "AZ-002",
        "Azure Service Principal Secret Exposed in Function App Settings",
        Severity.HIGH,
        """
        An Azure Function App's application settings contain what appears to be a
        service principal client secret (AZURE_CLIENT_SECRET or similar). If this
        principal has privileged roles, this represents a credential exposure risk.
        """,
        """
        MATCH (r:AzureResource {resource_type: 'microsoft.web/sites/functionapp'})
        WHERE r.has_env_vars = true
        MATCH (r)-[e:CROSS_CLOUD_LINK]->(tgt)
        WHERE e.cred_type CONTAINS 'azure'
        RETURN r.resource_id AS function_app,
               r.resource_group AS resource_group,
               e.cred_type AS credential_type,
               e.verified AS verified,
               tgt.identity_hint AS leaked_identity
        LIMIT 50
        """,
        "Move all secrets to Azure Key Vault. Use managed identity for Function Apps "
        "to eliminate the need for client secrets entirely.",
        ["T1552.001 - Credentials In Files"],
    ),

    # ── Azure: Federated/External SP with High Privilege ─────────────────────
    (
        "AZ-003",
        "External/Guest Service Principal with Contributor or Higher",
        Severity.HIGH,
        """
        A service principal from an external tenant or marked as a guest has been
        granted Contributor or higher role at subscription scope. External service
        principals are harder to monitor and revoke in an incident.
        """,
        """
        MATCH (p:AzurePrincipal {principal_type: 'ServicePrincipal'})
        WHERE p.metadata CONTAINS 'externalTenant' OR p.display_name CONTAINS 'Guest'
        MATCH (p)-[:ASSIGNED_ROLE]->(rd:RoleDefinition)
        WHERE rd.scope STARTS WITH '/subscriptions'
        RETURN p.object_id AS sp_id,
               p.display_name AS name,
               p.app_id AS app_id,
               collect(rd.role_id) AS roles_at_subscription_scope
        LIMIT 50
        """,
        "Review and restrict external SP access. Use guest access policies to limit "
        "external tenant service principals. Prefer managed identities for cross-tenant automation.",
        ["T1199 - Trusted Relationship"],
    ),

    # ── GCP: Service Account Impersonation Chain ──────────────────────────────
    (
        "GCP-001",
        "GCP Service Account Impersonation Escalation Chain",
        Severity.CRITICAL,
        """
        A service account has roles/iam.serviceAccountTokenCreator or
        roles/iam.serviceAccountUser on a more privileged service account.
        This allows the lower-privileged SA to generate tokens for the higher-privileged
        one, effectively impersonating it—a privilege escalation chain.
        """,
        """
        MATCH (low:GCPPrincipal {principal_type: 'serviceAccount'})
        -[e:HAS_BINDING]->(res:GCPResource)
        WHERE e.role IN [
          'roles/iam.serviceAccountTokenCreator',
          'roles/iam.serviceAccountUser',
          'roles/iam.serviceAccountAdmin'
        ]
        MATCH (high:GCPPrincipal {principal_type: 'serviceAccount'})
        WHERE high.email <> low.email
          AND high.project_id = low.project_id
        WITH low, high, e.role AS impersonation_role, res
        RETURN low.email AS attacker_sa,
               high.email AS target_sa,
               impersonation_role,
               res.resource_id AS via_resource
        LIMIT 50
        """,
        "Audit all serviceAccountTokenCreator and serviceAccountUser bindings. "
        "Apply Workload Identity Federation instead of user-managed keys. "
        "Use VPC Service Controls to limit SA token generation.",
        ["T1134.001 - Token Impersonation/Theft", "T1548 - Abuse Elevation Control Mechanism"],
    ),

    # ── GCP: Primitive Roles (Owner/Editor) ───────────────────────────────────
    (
        "GCP-002",
        "Primitive Role (Owner/Editor) Granted at Project Level",
        Severity.HIGH,
        """
        Primitive roles (roles/owner, roles/editor) grant extremely broad access across
        all resources in the project. These roles predate IAM and do not follow
        least-privilege. Their presence indicates a governance gap.
        """,
        """
        MATCH (p:GCPPrincipal)-[e:HAS_BINDING]->(r:GCPResource)
        WHERE e.role IN ['roles/owner', 'roles/editor', 'roles/viewer']
          AND r.resource_type = 'cloudresourcemanager/Project'
        RETURN p.email AS principal,
               p.principal_type AS type,
               e.role AS primitive_role,
               r.resource_id AS project
        ORDER BY
          CASE e.role
            WHEN 'roles/owner' THEN 1
            WHEN 'roles/editor' THEN 2
            ELSE 3
          END
        LIMIT 50
        """,
        "Replace primitive roles with predefined or custom roles scoped to specific services. "
        "Use IAM Recommender to identify unused permissions. For break-glass access, use "
        "roles/owner with JIT (Just-in-Time) provisioning via Privileged Access Manager.",
        ["T1078.004 - Cloud Accounts"],
    ),

    # ── GCP: SA Key Exposed in Cloud Function ─────────────────────────────────
    (
        "GCP-003",
        "Cross-Cloud Credential Found in GCP Cloud Function Environment",
        Severity.CRITICAL,
        """
        A GCP Cloud Function's environment variables contain credentials for another
        cloud provider (AWS or Azure). If the function is publicly invocable or
        compromised, this provides a pivot to the target cloud environment.
        """,
        """
        MATCH (r:GCPResource {resource_type: 'cloudfunctions.googleapis.com/Function'})
        WHERE r.has_env_vars = true
        MATCH (r)-[e:CROSS_CLOUD_LINK]->(tgt)
        RETURN r.resource_id AS cloud_function,
               r.project_id AS project,
               r.location AS region,
               e.cred_type AS credential_type,
               e.target_cloud AS target_cloud,
               e.verified AS verified,
               e.status AS verification_status,
               tgt.identity_hint AS target_identity
        ORDER BY e.verified DESC
        LIMIT 50
        """,
        "Migrate secrets to Secret Manager. Remove all hardcoded credentials from "
        "function environment variables. Use Workload Identity Federation for cross-cloud access.",
        ["T1552.001 - Credentials In Files", "T1552.005 - Cloud Instance Metadata API"],
    ),

    # ── Cross-Cloud: Verified Lateral Movement Path ───────────────────────────
    (
        "XC-001",
        "Confirmed Cross-Cloud Lateral Movement Path",
        Severity.CRITICAL,
        """
        A live, verified credential exists that enables movement from one cloud environment
        to another. The credential has been confirmed via a non-destructive WhoAmI call.
        This is a P0 finding requiring immediate credential rotation.
        """,
        """
        MATCH (src)-[e:CROSS_CLOUD_LINK {verified: true}]->(tgt)
        RETURN labels(src) AS source_labels,
               COALESCE(src.arn, src.resource_id, src.name) AS source_id,
               e.source_cloud AS source_cloud,
               e.target_cloud AS target_cloud,
               e.cred_type AS credential_type,
               tgt.identity_hint AS target_identity,
               e.account AS target_account,
               e.status AS verification_status
        ORDER BY e.target_cloud, source_id
        LIMIT 100
        """,
        "P0: Immediately rotate all affected credentials. Revoke the target identity's "
        "permissions while investigation is ongoing. Enable CloudTrail/Azure Monitor/GCP "
        "audit logs for the target identity to check for unauthorized activity.",
        ["T1078.004 - Cloud Accounts", "T1199 - Trusted Relationship",
         "T1552.001 - Credentials In Files"],
    ),

    # ── General: Principals with No MFA ──────────────────────────────────────
    (
        "AWS-007",
        "IAM User Without MFA Enabled",
        Severity.MEDIUM,
        """
        Human IAM users without MFA are susceptible to credential stuffing, phishing,
        and password spray attacks. Any compromise of the password directly yields
        console and API access.
        """,
        """
        MATCH (p:AWSPrincipal {principal_type: 'User'})
        WHERE NOT p.metadata CONTAINS '"mfa_active": true'
          AND NOT p.metadata CONTAINS 'mfa_active\": true'
        RETURN p.arn AS user_arn,
               p.name AS username,
               p.metadata AS metadata
        LIMIT 100
        """,
        "Enforce MFA via IAM policy condition (aws:MultiFactorAuthPresent). "
        "Use AWS Organizations SCPs to deny console access without MFA.",
        ["T1078.004 - Cloud Accounts"],
    ),
]


class PatternMatcher:
    """
    Runs Cypher pattern detection queries against the Neo4j graph.
    Returns structured Finding objects with affected nodes and remediation guidance.
    """

    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j"):
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self._driver = None

    async def connect(self):
        import logging as _logging  # noqa: PLC0415
        from neo4j import AsyncGraphDatabase  # noqa: PLC0415 — lazy import

        # Silence the neo4j driver's own notification logger which prints
        # GQL warnings directly to stderr regardless of our consume() calls.
        for _noisy in ("neo4j", "neo4j.notifications", "neo4j.io"):
            _logging.getLogger(_noisy).setLevel(_logging.ERROR)

        # notifications_min_severity="OFF" suppresses all GQL notifications
        # at the protocol level (neo4j-python-driver >= 5.14).
        # Fall back silently if the parameter isn't supported on older versions.
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
        logger.info("PatternMatcher connected to Neo4j")

    async def close(self):
        if self._driver:
            await self._driver.close()

    async def _run_query(self, cypher: str, parameters: dict | None = None) -> list[dict]:
        async with self._driver.session(database=self.database) as session:
            result = await session.run(cypher, parameters or {})
            records = await result.data()
            # Consume the result summary to prevent GQL notification spam on stderr.
            # Notifications for missing relationship types or property names are
            # expected during AWS-only scans (Azure/GCP relationships won't exist).
            try:
                summary = await result.consume()
                for notification in (summary.notifications or []):
                    sev = getattr(notification, "raw_severity", "").upper()
                    if sev not in ("WARNING", "INFORMATION"):
                        logger.debug(
                            "Neo4j notification [%s]: %s",
                            sev,
                            getattr(notification, "status_description", str(notification))[:120],
                        )
            except Exception:
                pass
            return records

    # Relationships that are only created when specific cloud data is imported.
    # Checks using these may return empty not because there are no issues,
    # but because the graph edges haven't been populated yet.
    _CONDITIONAL_RELATIONSHIPS = frozenset({
        "HAS_PERMISSION",    # created from resource policies (S3, Lambda)
        "CAN_ASSUME",        # created from IAM role trust policies (cross-account)
        "ASSIGNED_ROLE",     # created from Azure role assignments
        "HAS_BINDING",       # created from GCP IAM bindings
        "CROSS_CLOUD_LINK",  # created after credential verification
        "DEPLOYED_WITH_ROLE", # created from ECS/Lambda role associations
    })

    async def run_rule(self, rule: tuple, params: dict | None = None) -> Finding:
        import re as _re  # noqa: PLC0415
        rule_id, title, severity, description, cypher, recommendation, mitre = rule
        finding = Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description.strip(),
            recommendation=recommendation,
            mitre_attack=mitre,
        )
        try:
            records = await self._run_query(cypher.strip(), params)
            finding.raw_records = records
            finding.affected_nodes = records

            # If query returned no results AND uses conditional relationships,
            # flag it as "not yet evaluated" rather than silently passing.
            if not records:
                rel_matches = _re.findall(r'\[:[A-Z_]+\]', cypher)
                rel_matches = [m[2:-1] for m in rel_matches]
                unevaluated = [r for r in rel_matches if r in self._CONDITIONAL_RELATIONSHIPS]
                if unevaluated:
                    finding.not_evaluated = True
                    finding.not_evaluated_reason = (
                        f"Requires graph relationships not yet populated: "
                        f"{', '.join(unevaluated)}. "
                        f"Run a full scan with --import-graph to populate the graph, "
                        f"or these checks require S3/Lambda resource policies or "
                        f"cross-cloud data to be present."
                    )
                    logger.debug(
                        "Check %s not evaluated — missing relationships: %s",
                        rule_id, unevaluated
                    )
        except Exception as e:
            logger.warning("Rule %s query failed: %s", rule_id, e)
            finding.raw_records = [{"error": str(e)}]
        return finding

    async def run_all(
        self,
        severity_filter: Optional[Severity] = None,
        frameworks: Optional[list] = None,
        check_ids: Optional[list] = None,
        use_registry: bool = True,
        scan_start_ms: int = 0,
        active_clouds: Optional[set] = None,
    ) -> list[Finding]:
        """
        Run all checks. By default merges built-in RULES tuples with
        checks loaded from the YAML registry (CIS, OWASP, NIST, custom).

        active_clouds: Set of cloud names being scanned: {"aws"}, {"azure"}, {"gcp"},
            or any combination. Passed explicitly from the CLI — never derived from
            framework names — so compliance frameworks (NIST/OWASP/PCI/ISO) appearing
            in the always-run list do NOT incorrectly activate AWS rule execution.

        scan_start_ms: Neo4j-epoch millisecond timestamp recorded before the
            scan import. All checks use this to filter results to only nodes
            written in the current scan.
        """
        findings = []

        # Map rule ID prefix to the cloud that must be active for it to run.
        # AWS-* rules only run during --aws; AZ-* during --azure; GCP-* during --gcp.
        _rule_cloud_map = {
            "AWS": "aws",
            "AZ":  "azure",
            "GCP": "gcp",
        }

        # Use explicitly passed active_clouds. Fall back to deriving from
        # AWS-SPECIFIC framework prefixes ONLY — never from NIST/OWASP/PCI/ISO
        # since those are always-run compliance frameworks, not cloud selectors.
        if active_clouds is not None:
            _active_clouds = set(active_clouds)
        elif frameworks is None:
            _active_clouds = {"aws", "azure", "gcp"}
        else:
            fw_joined = " ".join(f.upper() for f in frameworks)
            _active_clouds: set[str] = set()
            # Only AWS-SPECIFIC prefixes count — not NIST/OWASP/PCI/ISO
            if any(x in fw_joined for x in ("CIS-AWS", "AWS-COMPUTE", "AWS-DATA")):
                _active_clouds.add("aws")
            if "AZURE" in fw_joined:
                _active_clouds.add("azure")
            if "GCP" in fw_joined:
                _active_clouds.add("gcp")
            # If nothing matched (e.g. only CROSS-CLOUD/CUSTOM/NIST/OWASP), run all clouds
            # so compliance checks surface findings regardless of cloud flag
            if not _active_clouds:
                _active_clouds = {"aws", "azure", "gcp"}

        # ── Built-in hardcoded rules ─────────────────────────────────
        for rule in RULES:
            rule_id, title, sev, description, cypher, recommendation, mitre = rule
            if severity_filter and sev != severity_filter:
                continue
            if check_ids and rule_id not in check_ids:
                continue

            # Skip rules that belong to a cloud not being scanned
            rule_prefix = rule_id.split("-")[0]  # "AWS", "AZ", "GCP"
            required_cloud = _rule_cloud_map.get(rule_prefix)
            if required_cloud and required_cloud not in _active_clouds:
                continue

            finding = await self.run_rule(rule)
            if finding.affected_nodes:
                findings.append(finding)
                logger.info("FINDING [%s] %s — %d affected", sev, title,
                            len(finding.affected_nodes))

        # ── YAML registry checks (CIS, OWASP, NIST, custom) ─────────
        if use_registry:
            try:
                from iamwatching.patterns.registry import get_registry  # noqa: PLC0415
                registry = get_registry()
                registry.load()
                yaml_checks = registry.all_checks(enabled_only=True)

                for check in yaml_checks:
                    if severity_filter and check.severity != severity_filter:
                        continue
                    if frameworks and not any(
                        fw.upper() in check.framework.upper() for fw in frameworks
                    ):
                        continue
                    if check_ids and check.id not in check_ids:
                        continue
                    # Skip if already run as a built-in (same ID)
                    already_run = any(r[0] == check.id for r in RULES)
                    if already_run:
                        continue

                    rule_tuple = (
                        check.id, check.title, check.severity,
                        check.description, check.cypher,
                        check.recommendation, check.mitre,
                    )
                    # Pass scan_start_ms as a Cypher parameter for all checks
                    # that use $scan_start in their WHERE clause.
                    # This scopes findings to nodes written in the current scan,
                    # preventing stale data from a previous cloud scan surfacing.
                    check_params = None
                    if scan_start_ms and "$scan_start" in check.cypher:
                        check_params = {"scan_start": scan_start_ms}
                    finding = await self.run_rule(rule_tuple, params=check_params)
                    if finding.affected_nodes:
                        findings.append(finding)
                        logger.info("FINDING [%s] %s — %d affected",
                                    check.severity, check.title,
                                    len(finding.affected_nodes))
            except Exception as e:
                logger.warning("Registry check loading failed: %s", e)

        _sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings.sort(key=lambda f: _sev_order.index(f.severity.value if hasattr(f.severity, "value") else str(f.severity)))
        return findings

    async def run_custom(self, cypher: str, title: str = "Custom Query") -> Finding:
        """Run an ad-hoc Cypher query as a Finding."""
        finding = Finding(
            rule_id="CUSTOM",
            title=title,
            severity=Severity.INFO,
            description="Custom Cypher query",
        )
        records = await self._run_query(cypher)
        finding.raw_records = records
        finding.affected_nodes = records
        return finding
