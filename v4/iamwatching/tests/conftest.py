"""
conftest.py — shared pytest fixtures for IamWatching tests.

Compatibility: pytest-asyncio >= 0.21, including 1.x series.
Sets fake AWS credentials before any test — required for moto + aioboto3.
"""

import os
import pytest


@pytest.fixture(scope="session", autouse=True)
def aws_credentials():
    """
    Set fake AWS credentials for the entire test session.
    Required for moto to intercept aiobotocore/aioboto3 HTTP calls —
    botocore resolves credentials before making any HTTP request,
    so fake creds must be present even though moto patches the HTTP layer.
    """
    saved = {
        k: os.environ.get(k)
        for k in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SECURITY_TOKEN",
            "AWS_SESSION_TOKEN",
            "AWS_DEFAULT_REGION",
        )
    }

    os.environ["AWS_ACCESS_KEY_ID"]     = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"]    = "testing"
    os.environ["AWS_SESSION_TOKEN"]     = "testing"
    os.environ["AWS_DEFAULT_REGION"]    = "us-east-1"

    yield

    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
