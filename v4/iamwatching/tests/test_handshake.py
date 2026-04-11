"""
Handshake / verifier tests.
No cloud SDK imports at module level — all mocked inside test bodies.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from iamwatching.handshake.verifier import (
    CredentialVerifier,
    VerificationResult,
    VerificationStatus,
    _verify_aws_key,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_cred(cred_type="aws_access_key", target_cloud="aws", raw_value="AKIAIOSFODNN7EXAMPLE"):
    """Build a minimal DiscoveredCredential-like object without importing scanners."""
    class _Cred:
        source_cloud    = "gcp"
        source_resource = "projects/proj/functions/fn"
        pass
    c = _Cred()
    c.cred_type    = cred_type
    c.target_cloud = target_cloud
    c.raw_value    = raw_value
    return c


# ── VerificationResult dataclass ─────────────────────────────────────────────

class TestVerificationResult:

    def test_defaults(self):
        r = VerificationResult(
            credential_source_cloud="aws",
            credential_source_resource="arn:aws:lambda:::fn",
            credential_type="aws_access_key",
            target_cloud="aws",
            status=VerificationStatus.INSUFFICIENT_DATA,
        )
        assert r.identity      is None
        assert r.account       is None
        assert r.verified_link is False
        assert r.error         is None

    def test_verified_link_flag(self):
        r = VerificationResult(
            credential_source_cloud="gcp",
            credential_source_resource="fn",
            credential_type="aws_access_key",
            target_cloud="aws",
            status=VerificationStatus.VALID,
            identity="arn:aws:iam::123:user/u",
            account="123456789012",
            verified_link=True,
        )
        assert r.verified_link is True
        assert r.status == VerificationStatus.VALID


# ── VerificationStatus enum ───────────────────────────────────────────────────

class TestVerificationStatus:

    def test_all_statuses_exist(self):
        expected = {"VALID", "INVALID", "RATE_LIMITED",
                    "NETWORK_ERROR", "INSUFFICIENT_DATA", "SKIPPED"}
        actual   = {s.value for s in VerificationStatus}
        assert expected == actual

    def test_string_comparison(self):
        assert VerificationStatus.VALID   == "VALID"
        assert VerificationStatus.INVALID == "INVALID"


# ── AWS key verification ──────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAWSVerifier:

    async def test_valid_key_returns_valid(self):
        mock_sts = AsyncMock()
        mock_sts.get_caller_identity.return_value = {
            "UserId":  "AIDAEXAMPLE",
            "Account": "123456789012",
            "Arn":     "arn:aws:iam::123456789012:user/test-user",
        }
        mock_session = MagicMock()
        mock_session.client.return_value.__aenter__ = AsyncMock(return_value=mock_sts)
        mock_session.client.return_value.__aexit__  = AsyncMock(return_value=None)

        with patch("iamwatching.handshake.verifier.aioboto3", create=True) as mock_boto:
            mock_boto.Session.return_value = mock_session
            # Also patch the lazy import inside the function
            import sys
            import types
            fake_aioboto3 = types.ModuleType("aioboto3")
            fake_aioboto3.Session = MagicMock(return_value=mock_session)
            sys.modules["aioboto3"] = fake_aioboto3

            result = await _verify_aws_key("AKIAIOSFODNN7EXAMPLE", "fakesecret")

        assert result.status      == VerificationStatus.VALID
        assert result.verified_link is True
        assert result.account     == "123456789012"

    async def test_insufficient_data_when_no_secret(self):
        verifier = CredentialVerifier()
        cred = _make_cred(cred_type="aws_access_key")
        result = await verifier.verify(cred, extra_context={})
        assert result.status == VerificationStatus.INSUFFICIENT_DATA

    async def test_skipped_for_unknown_cred_type(self):
        verifier = CredentialVerifier()
        cred = _make_cred(cred_type="totally_unknown_xyz")
        result = await verifier.verify(cred)
        assert result.status == VerificationStatus.SKIPPED

    async def test_azure_insufficient_without_tenant(self):
        verifier = CredentialVerifier()
        cred = _make_cred(cred_type="azure_client_secret", target_cloud="azure",
                          raw_value="someClientSecret")
        result = await verifier.verify(cred, extra_context={})
        assert result.status == VerificationStatus.INSUFFICIENT_DATA
        assert "tenant_id" in (result.error or "")

    async def test_gcp_insufficient_without_key_json(self):
        verifier = CredentialVerifier()
        cred = _make_cred(cred_type="gcp_service_account", target_cloud="gcp")
        result = await verifier.verify(cred, extra_context={})
        assert result.status == VerificationStatus.INSUFFICIENT_DATA

    async def test_verify_all_handles_multiple_creds(self):
        verifier = CredentialVerifier()
        creds = [_make_cred() for _ in range(4)]
        results = await verifier.verify_all(creds)
        # All should return INSUFFICIENT_DATA (no secret key provided)
        assert len(results) == 4
        assert all(r.status == VerificationStatus.INSUFFICIENT_DATA for r in results)

    async def test_verify_all_returns_list_of_results(self):
        verifier = CredentialVerifier()
        creds = [
            _make_cred("aws_access_key"),
            _make_cred("azure_client_secret"),
            _make_cred("gcp_service_account"),
        ]
        results = await verifier.verify_all(creds)
        assert isinstance(results, list)
        assert all(isinstance(r, VerificationResult) for r in results)

    async def test_semaphore_limits_concurrency(self):
        """CredentialVerifier with concurrency=2 should still process all creds."""
        verifier = CredentialVerifier(concurrency=2)
        creds = [_make_cred() for _ in range(6)]
        results = await verifier.verify_all(creds)
        assert len(results) == 6
