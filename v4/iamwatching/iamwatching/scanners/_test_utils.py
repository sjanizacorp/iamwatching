"""
Test utilities for AWSScanner — sync boto3 adapter that mimics the aioboto3
interface. Injected via AWSScanner(_session_factory=...) in tests so moto's
sync boto3 mock works without needing moto to support aiobotocore.

This is ONLY used in tests. Production code always uses aioboto3.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any


class _SyncClientWrapper:
    """Wraps a sync boto3 client to look like an async aioboto3 client."""

    def __init__(self, sync_client):
        self._client = sync_client

    def __getattr__(self, name: str):
        attr = getattr(self._client, name)
        if callable(attr):
            async def async_wrapper(*args, **kwargs):
                return await asyncio.to_thread(attr, *args, **kwargs)
            return async_wrapper
        return attr

    def get_paginator(self, operation_name: str):
        return _SyncPaginatorWrapper(
            self._client.get_paginator(operation_name)
        )


class _SyncPaginatorWrapper:
    """Wraps a sync boto3 paginator to be async-iterable."""

    def __init__(self, sync_paginator):
        self._paginator = sync_paginator

    def paginate(self, **kwargs):
        return _SyncPageIterator(self._paginator.paginate(**kwargs))


class _SyncPageIterator:
    """Async iterator over sync paginator pages."""

    def __init__(self, sync_iterator):
        self._pages = list(sync_iterator)  # collect all pages eagerly
        self._index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._index >= len(self._pages):
            raise StopAsyncIteration
        page = self._pages[self._index]
        self._index += 1
        return page


class _SyncSessionWrapper:
    """
    Wraps a sync boto3 session to look like an aioboto3 session.
    client() returns an async context manager yielding a _SyncClientWrapper.
    """

    def __init__(self, sync_session):
        self._session = sync_session

    def client(self, service_name: str, region_name: str = None, **kwargs):
        return _SyncClientContext(self._session, service_name, region_name, kwargs)


class _SyncClientContext:
    """Async context manager that yields a wrapped sync boto3 client."""

    def __init__(self, session, service_name, region_name, kwargs):
        self._session      = session
        self._service_name = service_name
        self._region_name  = region_name
        self._kwargs       = kwargs
        self._client       = None

    async def __aenter__(self):
        kw = dict(self._kwargs)
        if self._region_name:
            kw["region_name"] = self._region_name
        self._client = self._session.client(self._service_name, **kw)
        return _SyncClientWrapper(self._client)

    async def __aexit__(self, *args):
        if self._client:
            self._client.close()


def make_boto3_session_factory(boto3_session=None):
    """
    Return a callable that AWSScanner._session_factory can use.
    If boto3_session is None, creates a default boto3.Session().
    """
    import boto3  # noqa: PLC0415

    def factory():
        sess = boto3_session or boto3.Session()
        return _SyncSessionWrapper(sess)

    return factory
