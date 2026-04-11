"""
IamWatching — Structured Logging Module
========================================
Provides a unified, structured logging system across every module in IamWatching.

Features:
  - JSON-structured output for SIEM/log-aggregator ingestion
  - Human-readable Rich console output for interactive runs
  - Per-module child loggers with automatic context injection
  - Rotating file handler (10 MB / 5 backups) with optional audit log
  - Correlation ID propagation across the full scan pipeline
  - Sensitive value redaction (AWS keys, client secrets, tokens)
  - Structured event types: SCAN_START, SCAN_END, CRED_FOUND,
    CRED_VERIFIED, GRAPH_WRITE, FINDING, DEPLOY_STEP, ERROR
  - Phase timing with nanosecond precision
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.text import Text
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    Console = None
    RichHandler = None

# ─────────────────────────────────────────────────────────────────────────────
# Event types — each structured log record carries exactly one
# ─────────────────────────────────────────────────────────────────────────────

class EventType(str, Enum):
    SCAN_START       = "SCAN_START"
    SCAN_END         = "SCAN_END"
    CRED_FOUND       = "CRED_FOUND"
    CRED_VERIFIED    = "CRED_VERIFIED"
    GRAPH_WRITE      = "GRAPH_WRITE"
    PATTERN_RUN      = "PATTERN_RUN"
    FINDING          = "FINDING"
    DEPLOY_STEP      = "DEPLOY_STEP"
    DEPLOY_COMPLETE  = "DEPLOY_COMPLETE"
    DEPLOY_ERROR     = "DEPLOY_ERROR"
    DAEMON_POLL      = "DAEMON_POLL"
    DAEMON_DIFF      = "DAEMON_DIFF"
    AUTH_ERROR       = "AUTH_ERROR"
    NETWORK_ERROR    = "NETWORK_ERROR"
    ERROR            = "ERROR"
    INFO             = "INFO"
    DEBUG            = "DEBUG"


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive value redaction
# ─────────────────────────────────────────────────────────────────────────────

_REDACT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS secret access key (40-char base64)
    (re.compile(r'(?i)(aws.?secret.?access.?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})'), r'\1[REDACTED]'),
    # AWS session token (long base64)
    (re.compile(r'(?i)(aws.?session.?token\s*[=:]\s*)([A-Za-z0-9/+=]{100,})'), r'\1[REDACTED]'),
    # Azure client secret (any long alpha-numeric after known env var names)
    (re.compile(r'(?i)(azure.?client.?secret\s*[=:]\s*)([A-Za-z0-9\-._~]{20,})'), r'\1[REDACTED]'),
    # Bearer tokens in Authorization headers
    (re.compile(r'(Bearer\s+)([A-Za-z0-9\-_.~+/]+=*)'), r'\1[REDACTED]'),
    # GCP service account JSON private_key field
    (re.compile(r'("private_key"\s*:\s*")([^"]{20,})(")', re.DOTALL), r'\1[REDACTED]\3'),
    # Generic password= patterns
    (re.compile(r'(?i)(password\s*[=:]\s*)(\S{6,})'), r'\1[REDACTED]'),
]


def redact(text: str) -> str:
    """Apply all redaction patterns to a string."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ─────────────────────────────────────────────────────────────────────────────
# JSON formatter — emits one JSON object per log record
# ─────────────────────────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects for machine consumption.
    Injects: timestamp, level, logger, correlation_id, event_type, message,
             plus any extra fields passed via logger.info("msg", extra={...}).
    """

    def format(self, record: logging.LogRecord) -> str:
        # Pull structured extras (set by IamLogger methods)
        event_type = getattr(record, "event_type", EventType.INFO)
        correlation_id = getattr(record, "correlation_id", "")
        phase = getattr(record, "phase", "")
        cloud = getattr(record, "cloud", "")
        duration_ms = getattr(record, "duration_ms", None)
        extra_fields = getattr(record, "extra_fields", {})

        obj: dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "ms": int(record.created * 1000) % 1000,
            "level": record.levelname,
            "logger": record.name,
            "event": event_type.value if hasattr(event_type, "value") else str(event_type),
            "message": redact(record.getMessage()),
        }
        if correlation_id:
            obj["correlation_id"] = correlation_id
        if phase:
            obj["phase"] = phase
        if cloud:
            obj["cloud"] = cloud
        if duration_ms is not None:
            obj["duration_ms"] = duration_ms
        if extra_fields:
            # Redact every string value in extra_fields
            obj.update({
                k: redact(str(v)) if isinstance(v, str) else v
                for k, v in extra_fields.items()
            })
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(obj, default=str)


# ─────────────────────────────────────────────────────────────────────────────
# Rich console formatter — color-coded by event type
# ─────────────────────────────────────────────────────────────────────────────

_EVENT_STYLES: dict[str, str] = {
    EventType.SCAN_START:      "bold cyan",
    EventType.SCAN_END:        "cyan",
    EventType.CRED_FOUND:      "bold yellow",
    EventType.CRED_VERIFIED:   "bold red",
    EventType.GRAPH_WRITE:     "blue",
    EventType.PATTERN_RUN:     "magenta",
    EventType.FINDING:         "bold red",
    EventType.DEPLOY_STEP:     "green",
    EventType.DEPLOY_COMPLETE: "bold green",
    EventType.DEPLOY_ERROR:    "bold red",
    EventType.DAEMON_POLL:     "dim cyan",
    EventType.DAEMON_DIFF:     "yellow",
    EventType.AUTH_ERROR:      "bold red",
    EventType.NETWORK_ERROR:   "red",
    EventType.ERROR:           "bold red",
    EventType.INFO:            "white",
    EventType.DEBUG:           "dim",
}


# ─────────────────────────────────────────────────────────────────────────────
# IamLogger — the main interface for all logging in the codebase
# ─────────────────────────────────────────────────────────────────────────────

class IamLogger:
    """
    Structured logger for IamWatching.

    Usage:
        log = get_logger("aws_scanner")
        log.scan_start("aws", account_id="123456789012", regions=["us-east-1"])
        log.cred_found("gcp_api_key", source="lambda:my-fn", target_cloud="gcp")
        with log.timed_phase("graph_import"):
            ...
    """

    def __init__(
        self,
        name: str,
        correlation_id: Optional[str] = None,
        phase: Optional[str] = None,
        cloud: Optional[str] = None,
    ):
        self._logger = logging.getLogger(name)
        self.correlation_id = correlation_id or ""
        self.phase = phase or ""
        self.cloud = cloud or ""

    def child(self, suffix: str, **overrides) -> "IamLogger":
        """Create a child logger inheriting correlation_id."""
        return IamLogger(
            name=f"{self._logger.name}.{suffix}",
            correlation_id=overrides.get("correlation_id", self.correlation_id),
            phase=overrides.get("phase", self.phase),
            cloud=overrides.get("cloud", self.cloud),
        )

    def _emit(
        self,
        _log_level: int,
        event_type: EventType,
        message: str,
        **extra: Any,
    ) -> None:
        self._logger.log(
            _log_level,
            message,
            extra={
                "event_type": event_type,
                "correlation_id": self.correlation_id,
                "phase": self.phase,
                "cloud": self.cloud,
                "extra_fields": extra,
            },
        )

    # ── Scan lifecycle ──────────────────────────────────────────────────────

    def scan_start(self, cloud: str, **kwargs) -> None:
        self._emit(logging.INFO, EventType.SCAN_START,
                   f"[{cloud.upper()}] Scan starting", cloud=cloud, **kwargs)

    def scan_end(self, cloud: str, principals: int, resources: int,
                 creds_found: int, duration_ms: float) -> None:
        self._emit(logging.INFO, EventType.SCAN_END,
                   f"[{cloud.upper()}] Scan complete — {principals} principals, "
                   f"{resources} resources, {creds_found} potential creds",
                   cloud=cloud, principals=principals, resources=resources,
                   creds_found=creds_found, duration_ms=round(duration_ms, 1))

    # ── Credential discovery ────────────────────────────────────────────────

    def cred_found(self, cred_type: str, source_resource: str,
                   target_cloud: str, source_cloud: str) -> None:
        self._emit(logging.WARNING, EventType.CRED_FOUND,
                   f"Potential {target_cloud.upper()} credential ({cred_type}) "
                   f"found in {source_cloud} resource",
                   cred_type=cred_type, source_resource=source_resource,
                   target_cloud=target_cloud, source_cloud=source_cloud)

    def cred_verified(self, cred_type: str, source_resource: str,
                      target_cloud: str, identity: str, account: str,
                      verified: bool) -> None:
        level = logging.CRITICAL if verified else logging.INFO
        status = "LIVE — CONFIRMED CROSS-CLOUD PIVOT" if verified else "invalid/expired"
        self._emit(level, EventType.CRED_VERIFIED,
                   f"Credential verification: {status}",
                   cred_type=cred_type, source_resource=source_resource,
                   target_cloud=target_cloud, identity=identity,
                   account=account, verified=verified)

    # ── Graph operations ────────────────────────────────────────────────────

    def graph_write(self, operation: str, node_label: str,
                    count: int, duration_ms: float) -> None:
        self._emit(logging.DEBUG, EventType.GRAPH_WRITE,
                   f"Neo4j {operation}: {count} {node_label} nodes/edges",
                   operation=operation, node_label=node_label,
                   count=count, duration_ms=round(duration_ms, 1))

    # ── Pattern detection ───────────────────────────────────────────────────

    def pattern_run(self, rule_id: str, title: str) -> None:
        self._emit(logging.DEBUG, EventType.PATTERN_RUN,
                   f"Running rule {rule_id}: {title}",
                   rule_id=rule_id, title=title)

    def finding(self, rule_id: str, severity: str, title: str,
                affected_count: int) -> None:
        level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH":     logging.ERROR,
            "MEDIUM":   logging.WARNING,
            "LOW":      logging.INFO,
        }.get(severity, logging.INFO)
        self._emit(level, EventType.FINDING,
                   f"[{severity}] {rule_id}: {title} — {affected_count} affected",
                   rule_id=rule_id, severity=severity, title=title,
                   affected_count=affected_count)

    # ── Deployment ──────────────────────────────────────────────────────────

    def deploy_step(self, step: str, detail: str = "") -> None:
        self._emit(logging.INFO, EventType.DEPLOY_STEP,
                   f"[DEPLOY] {step}" + (f" — {detail}" if detail else ""),
                   step=step, detail=detail)

    def deploy_complete(self, step: str, duration_ms: float) -> None:
        self._emit(logging.INFO, EventType.DEPLOY_COMPLETE,
                   f"[DEPLOY] ✓ {step} completed",
                   step=step, duration_ms=round(duration_ms, 1))

    def deploy_error(self, step: str, error: str) -> None:
        self._emit(logging.ERROR, EventType.DEPLOY_ERROR,
                   f"[DEPLOY] ✗ {step} failed: {error}",
                   step=step, error=error)

    # ── Daemon ──────────────────────────────────────────────────────────────

    def daemon_poll(self, account: str, fingerprint: str,
                    roles: int, users: int, policies: int) -> None:
        self._emit(logging.DEBUG, EventType.DAEMON_POLL,
                   f"[DAEMON] Poll complete for {account}",
                   account=account, fingerprint=fingerprint,
                   roles=roles, users=users, policies=policies)

    def daemon_diff(self, account: str, added: int, removed: int,
                    modified: int) -> None:
        level = logging.WARNING if (added + removed + modified) > 0 else logging.DEBUG
        self._emit(level, EventType.DAEMON_DIFF,
                   f"[DAEMON] IAM delta — +{added} added, -{removed} removed, "
                   f"~{modified} modified",
                   account=account, added=added, removed=removed, modified=modified)

    # ── Generic helpers ─────────────────────────────────────────────────────

    def info(self, msg: str, **kwargs) -> None:
        self._emit(logging.INFO, EventType.INFO, msg, **kwargs)

    def debug(self, msg: str, **kwargs) -> None:
        self._emit(logging.DEBUG, EventType.DEBUG, msg, **kwargs)

    def warning(self, msg: str, **kwargs) -> None:
        self._emit(logging.WARNING, EventType.INFO, msg, **kwargs)

    def error(self, msg: str, **kwargs) -> None:
        self._emit(logging.ERROR, EventType.ERROR, msg, **kwargs)

    def exception(self, msg: str, exc: Optional[Exception] = None, **kwargs) -> None:
        self._logger.exception(
            redact(msg),
            extra={
                "event_type": EventType.ERROR,
                "correlation_id": self.correlation_id,
                "phase": self.phase,
                "cloud": self.cloud,
                "extra_fields": kwargs,
            },
        )

    # ── Timing context manager ──────────────────────────────────────────────

    @contextmanager
    def timed_phase(self, phase_name: str, cloud: str = ""):
        start = time.perf_counter()
        self.info(f"Phase [{phase_name}] starting", phase=phase_name, cloud=cloud)
        try:
            yield
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            self._emit(logging.ERROR, EventType.ERROR,
                       f"Phase [{phase_name}] FAILED after {elapsed:.0f}ms: {e}",
                       phase=phase_name, duration_ms=round(elapsed, 1), error=str(e))
            raise
        else:
            elapsed = (time.perf_counter() - start) * 1000
            self.info(f"Phase [{phase_name}] complete",
                      phase=phase_name, duration_ms=round(elapsed, 1), cloud=cloud)


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup — call once at process startup
# ─────────────────────────────────────────────────────────────────────────────

_CONFIGURED = False
_rich_console = Console(stderr=True) if _RICH_AVAILABLE else None


def configure_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    json_file: bool = True,
    audit_file: bool = True,
    console_json: bool = False,
    correlation_id: Optional[str] = None,
) -> str:
    """
    Configure the global logging system. Call once at startup.

    Args:
        level:          Root log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
        log_dir:        Directory for log files. Defaults to ./logs/
        json_file:      Write JSON-structured logs to iamwatching.jsonl
        audit_file:     Write CRITICAL/WARNING audit events to audit.jsonl
        console_json:   Emit JSON to stderr instead of Rich human-readable
        correlation_id: Optional run ID to inject into all records

    Returns:
        The correlation_id used for this run (auto-generated if not supplied)
    """
    global _CONFIGURED
    if _CONFIGURED:
        return correlation_id or ""

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    run_id = correlation_id or str(uuid.uuid4())[:8]

    root = logging.getLogger("iamwatching")
    root.setLevel(logging.DEBUG)  # handlers filter individually
    root.propagate = False

    # ── Console handler ─────────────────────────────────────────────────────
    if console_json or not _RICH_AVAILABLE:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(JSONFormatter())
        console_handler.setLevel(numeric_level)
    else:
        console_handler = RichHandler(
            console=_rich_console,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            show_path=False,
            markup=True,
            log_time_format="[%H:%M:%S]",
        )
        console_handler.setLevel(numeric_level)

    root.addHandler(console_handler)

    # ── File handlers ───────────────────────────────────────────────────────
    if log_dir is not None or json_file or audit_file:
        log_path = Path(log_dir) if log_dir else Path.cwd() / "logs"
        log_path.mkdir(parents=True, exist_ok=True)

        if json_file:
            # Rotating: 10 MB per file, 5 backups
            jsonl_handler = logging.handlers.RotatingFileHandler(
                log_path / "iamwatching.jsonl",
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            jsonl_handler.setFormatter(JSONFormatter())
            jsonl_handler.setLevel(logging.DEBUG)  # capture everything
            root.addHandler(jsonl_handler)

        if audit_file:
            # Audit log: only WARNING and above (creds, findings, errors)
            audit_handler = logging.handlers.RotatingFileHandler(
                log_path / "audit.jsonl",
                maxBytes=10 * 1024 * 1024,
                backupCount=10,
                encoding="utf-8",
            )
            audit_handler.setFormatter(JSONFormatter())
            audit_handler.setLevel(logging.WARNING)
            root.addHandler(audit_handler)

    _CONFIGURED = True
    startup_logger = IamLogger("iamwatching.setup", correlation_id=run_id)
    startup_logger.info(
        "Logging configured",
        level=level,
        log_dir=str(log_dir or "logs/"),
        json_file=json_file,
        audit_file=audit_file,
        run_id=run_id,
    )
    return run_id


def get_logger(
    module: str,
    correlation_id: Optional[str] = None,
    phase: Optional[str] = None,
    cloud: Optional[str] = None,
) -> IamLogger:
    """
    Get a structured IamLogger for a module.

    Usage:
        from iamwatching.logging_module import get_logger
        log = get_logger("aws_scanner", cloud="aws")
        log.scan_start("aws", account_id="123")
    """
    return IamLogger(
        name=f"iamwatching.{module}",
        correlation_id=correlation_id,
        phase=phase,
        cloud=cloud,
    )


def new_correlation_id() -> str:
    """Generate a fresh 8-char hex correlation ID for a run."""
    return str(uuid.uuid4())[:8]
