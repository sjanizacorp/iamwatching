"""
IamWatching Structured Logging Module
"""
from .logger import (
    IamLogger,
    EventType,
    JSONFormatter,
    configure_logging,
    get_logger,
    new_correlation_id,
    redact,
)

__all__ = [
    "IamLogger",
    "EventType",
    "JSONFormatter",
    "configure_logging",
    "get_logger",
    "new_correlation_id",
    "redact",
]
