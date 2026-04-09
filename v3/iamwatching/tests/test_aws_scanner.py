"""
AWS Scanner tests — v1.3.0
==========================
Pure-Python tests: always run, zero cloud SDK deps.
Moto integration tests: run when moto + boto3 are installed.

Key design: moto + aiobotocore have compatibility issues (bytes-not-awaitable).
We bypass this entirely by injecting a sync boto3 session into AWSScanner
via _session_factory=make_boto3_session_factory(). The adapter wraps every
sync boto3 call in asyncio.to_thread() so the scanner's async interface is
satisfied without aiobotocore ever being invoked.
"""
from __future__ import annotations

import json
import pytest

from iamwatching.scanners.aws_scanner import (
    AWSScanner,
    AWSScanResult,
    AWSPrincipal,
    AWSResource,
    DiscoveredCredential,
    _scan_for_creds,
    CROSS_CLOUD_PATTERNS,
)

# ── Test fixtures ─────────────────────────────────────────────────────────────
GCP_API_KEY  = "AIzaSy" + "A" * 33
AWS_KEY      = "AKIAIOSFODNN7EXAMPLE"
AZURE_SECRET = "AZURE_CLIENT_SECRET=Abcdefghij1234567890XYZ"

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# ── Moto availability ─────────────────────────────────────────────────────────
def _moto_available() -> bool:
    try:
        import moto   # noqa: F401
        import boto3  # noqa: F401
        from moto import mock_aws as _  # noqa: F401
        return True
    except ImportError:
        return False

MOTO_AVAILABLE = _moto_available()
skip_no_moto   = pytest.mark.skipif(
    not MOTO_AVAILABLE,
    reason="moto/boto3 not installed",
)


# ─────────────────────────────────────────────────────────────────────────────
# Pure-Python tests — no cloud SDK deps, always run
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossCloudPatternDetection:

    def test_detects_gcp_api_key(self):
        creds = _scan_for_creds(GCP_API_KEY, "fn", "lambda:Function", "123", "us-east-1")
        assert any(c.cred_type == "gcp_api_key" for c in creds)
        assert all(c.target_cloud == "gcp" for c in creds)

    def test_detects_aws_access_key(self):
        creds = _scan_for_creds(f"KEY={AWS_KEY}", "fn", "lambda:Function", "111", "us-east-1")
        assert any(c.cred_type == "aws_access_key" for c in creds)

    def test_detects_gcp_service_account_json(self):
        text  = '{"type": "service_account", "project_id": "proj"}'
        creds = _scan_for_creds(text, "fn", "lambda:Function", "111", "us-east-1")
        assert any(c.cred_type == "gcp_service_account" for c in creds)

    def test_detects_azure_client_secret(self):
        creds = _scan_for_creds(AZURE_SECRET, "fn", "lambda:Function", "111", "us-east-1")
        assert any(c.cred_type == "azure_client_secret" for c in creds)

    def test_no_false_positives(self):
        assert _scan_for_creds("DB_HOST=localhost PORT=5432", "fn", "t", "a", "us-east-1") == []

    def test_empty_string_returns_empty(self):
        assert _scan_for_creds("", "r", "t", "a", "us-east-1") == []

    def test_raw_value_truncated_at_120(self):
        text  = "AZURE_CLIENT_SECRET=" + "x" * 200
        creds = _scan_for_creds(text, "fn", "lambda:Function", "111", "us-east-1")
        assert all(len(c.raw_value) <= 120 for c in creds)

    def test_multiple_cred_types_in_one_text(self):
        text  = f"{AWS_KEY} {GCP_API_KEY} {AZURE_SECRET}"
        types = {c.cred_type for c in _scan_for_creds(text, "r", "t", "a", "us-east-1")}
        assert "aws_access_key"      in types
        assert "gcp_api_key"         in types
        assert "azure_client_secret" in types

    def test_source_fields_populated(self):
        creds = _scan_for_creds(
            GCP_API_KEY, "arn:aws:lambda:us-east-1:123:function:fn",
            "lambda:Function", "123456789", "us-east-1",
        )
        assert creds
        c = creds[0]
        assert c.source_cloud         == "aws"
        assert c.account_id           == "123456789"
        assert c.region               == "us-east-1"
        assert c.source_resource_type == "lambda:Function"

    def test_gcp_key_regex_accepts_correct_length(self):
        assert CROSS_CLOUD_PATTERNS["gcp_api_key"].search(GCP_API_KEY)

    def test_gcp_key_regex_rejects_too_short(self):
        assert not CROSS_CLOUD_PATTERNS["gcp_api_key"].search("AIza_short")

    def test_aws_key_regex_accepts_valid(self):
        assert CROSS_CLOUD_PATTERNS["aws_access_key"].search(AWS_KEY)

    def test_aws_key_regex_rejects_invalid(self):
        assert not CROSS_CLOUD_PATTERNS["aws_access_key"].search("NOTANAWSKEY12345678")

    def test_azure_raw_value_excludes_env_var_name(self):
        creds = _scan_for_creds(AZURE_SECRET, "r", "t", "a", "us-east-1")
        az    = [c for c in creds if c.cred_type == "azure_client_secret"]
        assert az
        assert "AZURE_CLIENT_SECRET" not in az[0].raw_value

    def test_source_cloud_always_aws(self):
        creds = _scan_for_creds(GCP_API_KEY, "r", "t", "a", "eu-west-1")
        assert all(c.source_cloud == "aws" for c in creds)


class TestDataClasses:

    def test_principal_defaults(self):
        p = AWSPrincipal(arn="arn:aws:iam::123:user/u", principal_type="User",
                         account_id="123", name="u")
        assert p.attached_policies == [] and p.inline_policies == []
        assert p.tags == {} and p.metadata == {}

    def test_resource_defaults(self):
        r = AWSResource(arn="arn:aws:s3:::b", resource_type="s3:Bucket",
                        account_id="123", region="us-east-1", name="b")
        assert r.resource_policy is None
        assert r.env_vars == {} and r.discovered_creds == []

    def test_scan_result_defaults(self):
        result = AWSScanResult(account_id="123456789012", region="us-east-1")
        assert result.principals == [] and result.resources == []
        assert result.discovered_credentials == []

    def test_scanner_instantiates_without_sdk(self):
        s = AWSScanner(profile="p", regions=["us-east-1", "eu-west-1"])
        assert s.profile == "p" and s.regions == ["us-east-1", "eu-west-1"]

    def test_scanner_default_region(self):
        assert AWSScanner().regions == ["us-east-1"]

    def test_scanner_accepts_session_factory(self):
        """_session_factory is accepted and stored without error."""
        factory = lambda: None  # noqa: E731
        s = AWSScanner(_session_factory=factory)
        assert s._session_factory is factory


# ─────────────────────────────────────────────────────────────────────────────
# Moto integration tests
#
# Strategy: inject a sync boto3 session via _session_factory so we bypass
# aiobotocore entirely. The _SyncSessionWrapper in _test_utils.py wraps
# every boto3 call in asyncio.to_thread() so AWSScanner's async interface
# is satisfied. moto patches the sync boto3 HTTP layer — no aiobotocore needed.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAWSScannerMoto:

    def _make_scanner(self, boto3_session):
        """Create an AWSScanner that uses the given boto3 session (via adapter)."""
        from iamwatching.scanners._test_utils import make_boto3_session_factory  # noqa: PLC0415
        return AWSScanner(
            regions=["us-east-1"],
            _session_factory=make_boto3_session_factory(boto3_session),
        )

    @skip_no_moto
    async def test_scan_finds_users_and_roles(self):
        from moto import mock_aws  # noqa: PLC0415
        import boto3               # noqa: PLC0415
        with mock_aws():
            sess = boto3.Session(region_name="us-east-1")
            iam  = sess.client("iam")
            iam.create_user(UserName="test-user")
            iam.create_role(RoleName="test-role",
                            AssumeRolePolicyDocument=_LAMBDA_TRUST)
            result = await self._make_scanner(sess).scan()

        users = [p.name for p in result.principals if p.principal_type == "User"]
        roles = [p.name for p in result.principals if p.principal_type == "Role"]
        assert "test-user" in users, f"test-user not in {users}"
        assert "test-role" in roles, f"test-role not in {roles}"

    @skip_no_moto
    async def test_scan_extracts_managed_policies(self):
        from moto import mock_aws  # noqa: PLC0415
        import boto3               # noqa: PLC0415
        with mock_aws():
            sess = boto3.Session(region_name="us-east-1")
            iam  = sess.client("iam")
            iam.create_policy(
                PolicyName="test-policy",
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
                }),
            )
            result = await self._make_scanner(sess).scan()

        names = [p.get("PolicyName") for p in result.managed_policies]
        assert "test-policy" in names, f"test-policy not in {names}"

    @skip_no_moto
    async def test_cross_account_trust_preserved(self):
        from moto import mock_aws  # noqa: PLC0415
        import boto3               # noqa: PLC0415
        with mock_aws():
            sess = boto3.Session(region_name="us-east-1")
            iam  = sess.client("iam")
            iam.create_role(
                RoleName="cross-account-role",
                AssumeRolePolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow",
                                   "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                                   "Action": "sts:AssumeRole"}],
                }),
            )
            result = await self._make_scanner(sess).scan()

        roles = [p for p in result.principals if p.name == "cross-account-role"]
        assert len(roles) == 1
        stmts = roles[0].metadata.get("assume_role_policy", {}).get("Statement", [])
        assert any("999999999999" in str(s.get("Principal", {})) for s in stmts)

    @skip_no_moto
    async def test_lambda_env_vars_scanned_for_credentials(self):
        from moto import mock_aws  # noqa: PLC0415
        import boto3               # noqa: PLC0415
        with mock_aws():
            sess = boto3.Session(region_name="us-east-1")
            iam  = sess.client("iam")
            lam  = sess.client("lambda", region_name="us-east-1")
            role_arn = iam.create_role(
                RoleName="lambda-role",
                AssumeRolePolicyDocument=_LAMBDA_TRUST,
            )["Role"]["Arn"]
            lam.create_function(
                FunctionName="leaky-fn",
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": b"def handler(e,c): pass"},
                Environment={"Variables": {"GCP_KEY": GCP_API_KEY}},
            )
            result = await self._make_scanner(sess).scan()

        assert result.discovered_credentials, "Expected at least one discovered credential"
        gcp = [c for c in result.discovered_credentials if c.target_cloud == "gcp"]
        assert gcp, "Expected at least one GCP credential"
        assert gcp[0].source_resource_type == "lambda:Function"

    @skip_no_moto
    async def test_scan_result_account_id_is_12_digits(self):
        from moto import mock_aws  # noqa: PLC0415
        import boto3               # noqa: PLC0415
        with mock_aws():
            sess   = boto3.Session(region_name="us-east-1")
            result = await self._make_scanner(sess).scan()

        assert result.account_id, "account_id should not be empty"
        assert len(result.account_id) == 12, f"Expected 12 digits, got {result.account_id!r}"
        assert result.account_id.isdigit(), f"account_id not numeric: {result.account_id!r}"
