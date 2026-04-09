"""
Handshake / Credential Verifier
================================
Non-destructive WhoAmI verification of discovered cross-cloud credentials.
All cloud SDK imports are deferred inside function bodies.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    VALID               = "VALID"
    INVALID             = "INVALID"
    RATE_LIMITED        = "RATE_LIMITED"
    NETWORK_ERROR       = "NETWORK_ERROR"
    INSUFFICIENT_DATA   = "INSUFFICIENT_DATA"
    SKIPPED             = "SKIPPED"


@dataclass
class VerificationResult:
    credential_source_cloud:    str
    credential_source_resource: str
    credential_type:            str
    target_cloud:               str
    status:                     VerificationStatus
    identity:   Optional[str]  = None
    account:    Optional[str]  = None
    raw_response: Optional[dict] = None
    error:      Optional[str]  = None
    verified_link: bool        = False


async def _verify_aws_key(
    access_key_id: str,
    secret_access_key: str,
    session_token: Optional[str] = None,
) -> VerificationResult:
    result = VerificationResult(
        credential_source_cloud="unknown",
        credential_source_resource="unknown",
        credential_type="aws_access_key",
        target_cloud="aws",
        status=VerificationStatus.INSUFFICIENT_DATA,
    )
    try:
        import aioboto3  # noqa: PLC0415
        from botocore.exceptions import ClientError  # noqa: PLC0415
        session = aioboto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
        )
        async with session.client("sts") as sts:
            identity = await sts.get_caller_identity()
        result.status    = VerificationStatus.VALID
        result.identity  = identity.get("Arn")
        result.account   = identity.get("Account")
        result.raw_response = {k: identity.get(k) for k in ("UserId", "Account", "Arn")}
        result.verified_link = True
    except Exception as e:
        # Lazy import for ClientError check
        try:
            from botocore.exceptions import ClientError  # noqa: PLC0415
            if isinstance(e, ClientError):
                code = e.response["Error"]["Code"]
                if code in ("InvalidClientTokenId", "AuthFailure", "InvalidSignatureException"):
                    result.status = VerificationStatus.INVALID
                elif code == "Throttling":
                    result.status = VerificationStatus.RATE_LIMITED
                else:
                    result.status = VerificationStatus.INVALID
            else:
                result.status = VerificationStatus.NETWORK_ERROR
        except ImportError:
            result.status = VerificationStatus.NETWORK_ERROR
        result.error = str(e)
    return result


async def _verify_azure_service_principal(
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> VerificationResult:
    result = VerificationResult(
        credential_source_cloud="unknown",
        credential_source_resource="unknown",
        credential_type="azure_client_secret",
        target_cloud="azure",
        status=VerificationStatus.INSUFFICIENT_DATA,
    )
    try:
        import aiohttp  # noqa: PLC0415
        token_url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_body = {
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url, data=token_body,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()

        if "error" in data:
            result.status = VerificationStatus.INVALID
            result.error  = data.get("error_description", data["error"])
            return result

        access_token = data.get("access_token", "")
        try:
            payload_b64 = access_token.split(".")[1]
            padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            result.status   = VerificationStatus.VALID
            result.identity = payload.get("appid") or payload.get("oid")
            result.account  = payload.get("tid")
            result.raw_response = {k: payload.get(k) for k in ("appid", "oid", "tid", "roles")}
            result.verified_link = True
        except Exception as decode_err:
            result.status        = VerificationStatus.VALID
            result.verified_link = True
            result.error = f"Token acquired but JWT decode failed: {decode_err}"
    except Exception as e:
        result.status = VerificationStatus.NETWORK_ERROR
        result.error  = str(e)
    return result


async def _verify_gcp_service_account_key(key_json: dict) -> VerificationResult:
    result = VerificationResult(
        credential_source_cloud="unknown",
        credential_source_resource="unknown",
        credential_type="gcp_service_account",
        target_cloud="gcp",
        status=VerificationStatus.INSUFFICIENT_DATA,
    )
    try:
        import aiohttp  # noqa: PLC0415
        import google.oauth2.service_account as sa_module  # noqa: PLC0415
        import google.auth.transport.requests as ga_requests  # noqa: PLC0415

        creds = sa_module.Credentials.from_service_account_info(
            key_json,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        request = ga_requests.Request()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: creds.refresh(request))

        async with aiohttp.ClientSession() as session:
            url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={creds.token}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = await resp.json()
                if resp.status == 200:
                    result.status        = VerificationStatus.VALID
                    result.identity      = key_json.get("client_email")
                    result.account       = key_json.get("project_id")
                    result.raw_response  = data
                    result.verified_link = True
                else:
                    result.status = VerificationStatus.INVALID
                    result.error  = data.get("error_description", str(data))
    except Exception as e:
        result.status = VerificationStatus.INVALID
        result.error  = str(e)
    return result


class CredentialVerifier:
    def __init__(self, concurrency: int = 5):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def verify(
        self,
        discovered_cred,
        extra_context: Optional[dict] = None,
    ) -> VerificationResult:
        ctx   = extra_context or {}
        ctype = discovered_cred.cred_type

        async with self.semaphore:
            if ctype == "aws_access_key":
                secret = ctx.get("aws_secret_access_key", "")
                if not secret:
                    r = VerificationResult(
                        credential_source_cloud=discovered_cred.source_cloud,
                        credential_source_resource=discovered_cred.source_resource,
                        credential_type=ctype, target_cloud="aws",
                        status=VerificationStatus.INSUFFICIENT_DATA,
                        error="No secret key available",
                    )
                    return r
                r = await _verify_aws_key(
                    discovered_cred.raw_value, secret, ctx.get("aws_session_token")
                )

            elif ctype == "azure_client_secret":
                tenant_id = ctx.get("azure_tenant_id", "")
                client_id = ctx.get("azure_client_id", "")
                if not (tenant_id and client_id):
                    r = VerificationResult(
                        credential_source_cloud=discovered_cred.source_cloud,
                        credential_source_resource=discovered_cred.source_resource,
                        credential_type=ctype, target_cloud="azure",
                        status=VerificationStatus.INSUFFICIENT_DATA,
                        error="Missing tenant_id or client_id",
                    )
                    return r
                r = await _verify_azure_service_principal(
                    tenant_id, client_id, discovered_cred.raw_value
                )

            elif ctype == "gcp_service_account":
                key_json_str = ctx.get("gcp_key_json", "")
                if not key_json_str:
                    r = VerificationResult(
                        credential_source_cloud=discovered_cred.source_cloud,
                        credential_source_resource=discovered_cred.source_resource,
                        credential_type=ctype, target_cloud="gcp",
                        status=VerificationStatus.INSUFFICIENT_DATA,
                        error="No GCP key JSON available",
                    )
                    return r
                try:
                    key_json = json.loads(key_json_str)
                except json.JSONDecodeError as e:
                    r = VerificationResult(
                        credential_source_cloud=discovered_cred.source_cloud,
                        credential_source_resource=discovered_cred.source_resource,
                        credential_type=ctype, target_cloud="gcp",
                        status=VerificationStatus.INSUFFICIENT_DATA,
                        error=f"Invalid JSON: {e}",
                    )
                    return r
                r = await _verify_gcp_service_account_key(key_json)

            else:
                r = VerificationResult(
                    credential_source_cloud=discovered_cred.source_cloud,
                    credential_source_resource=discovered_cred.source_resource,
                    credential_type=ctype,
                    target_cloud=discovered_cred.target_cloud,
                    status=VerificationStatus.SKIPPED,
                    error=f"No verifier for cred_type={ctype}",
                )
                return r

            r.credential_source_cloud    = discovered_cred.source_cloud
            r.credential_source_resource = discovered_cred.source_resource
            return r

    async def verify_all(
        self,
        discovered_creds: list,
        context_map: Optional[dict] = None,
    ) -> list[VerificationResult]:
        context_map = context_map or {}
        tasks = [
            self.verify(cred, context_map.get(cred.source_resource))
            for cred in discovered_creds
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, VerificationResult)]
        verified = sum(1 for r in valid if r.verified_link)
        log.info("Verification: %d/%d live cross-cloud links", verified, len(valid))
        return valid
