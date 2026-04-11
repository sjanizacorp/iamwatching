"""
Check Registry
==============
Loads, validates, and manages detection checks from YAML files.
Supports built-in checks (CIS, OWASP, NIST) and user-defined custom checks.

Directory layout (relative to project root):
  checks/
    builtin/          built-in checks shipped with IamWatching
      cis_aws.yaml
      owasp_cloud.yaml
      nist_csf.yaml
    custom/           user checks (never overwritten by updates)
      *.yaml

Each YAML file defines a framework and a list of checks. Each check has:
  id, title, severity, description, cypher, recommendation, mitre, references
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from iamwatching.patterns.matcher import Severity, Finding

log = logging.getLogger(__name__)


@dataclass
class CheckDefinition:
    """A single detection check loaded from YAML."""
    id: str
    title: str
    severity: Severity
    description: str
    cypher: str
    framework: str
    recommendation: str = ""
    mitre: list = field(default_factory=list)
    references: list = field(default_factory=list)
    enabled: bool = True
    source_file: str = ""


class CheckRegistry:
    """
    Loads and manages all check definitions.
    Merges built-in checks with custom checks; custom checks with the same ID
    override built-ins.
    """

    def __init__(self, checks_dir: Optional[Path] = None):
        if checks_dir is None:
            # Default: checks/ directory next to the project root
            checks_dir = _find_checks_dir()
        self.checks_dir = checks_dir
        self._checks: dict[str, CheckDefinition] = {}
        self._loaded = False

    def load(self, force: bool = False) -> int:
        """Load all checks from YAML. Returns count of checks loaded."""
        if self._loaded and not force:
            return len(self._checks)

        self._checks.clear()

        # Load built-ins first
        builtin_dir = self.checks_dir / "builtin"
        if builtin_dir.exists():
            for yaml_file in sorted(builtin_dir.glob("*.yaml")):
                self._load_file(yaml_file)

        # Load custom checks (override built-ins with same ID)
        custom_dir = self.checks_dir / "custom"
        if custom_dir.exists():
            for yaml_file in sorted(custom_dir.glob("*.yaml")):
                self._load_file(yaml_file)

        self._loaded = True
        log.info("CheckRegistry: loaded %d checks from %s", len(self._checks), self.checks_dir)
        return len(self._checks)

    def _load_file(self, path: Path) -> int:
        """Load checks from one YAML file. Returns count added."""
        count = 0
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "checks" not in data:
                log.debug("Skipping %s (no 'checks' key)", path.name)
                return 0

            framework = data.get("framework", path.stem)
            for raw in data.get("checks", []):
                try:
                    check = _parse_check(raw, framework, str(path))
                    if check.id in self._checks:
                        log.debug("Custom check %s overrides built-in", check.id)
                    self._checks[check.id] = check
                    count += 1
                except Exception as e:
                    log.warning("Skipping malformed check in %s: %s", path.name, e)

            log.debug("Loaded %d checks from %s (%s)", count, path.name, framework)
        except yaml.YAMLError as e:
            log.error("YAML parse error in %s: %s", path, e)
        except Exception as e:
            log.error("Failed to load %s: %s", path, e)
        return count

    def all_checks(self, enabled_only: bool = True) -> list[CheckDefinition]:
        if not self._loaded:
            self.load()
        checks = list(self._checks.values())
        if enabled_only:
            checks = [c for c in checks if c.enabled]
        return sorted(checks, key=lambda c: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(c.severity.value),
            c.id,
        ))

    def get(self, check_id: str) -> Optional[CheckDefinition]:
        if not self._loaded:
            self.load()
        return self._checks.get(check_id)

    def by_framework(self, framework: str) -> list[CheckDefinition]:
        return [c for c in self.all_checks() if c.framework == framework]

    def frameworks(self) -> list[str]:
        return sorted({c.framework for c in self.all_checks()})

    def add_custom(self, check_def: dict, framework: str = "CUSTOM", filename: str = "custom_runtime.yaml") -> CheckDefinition:
        """Add a check at runtime (not persisted to disk)."""
        effective_framework = check_def.get("framework", framework)
        check = _parse_check(check_def, effective_framework, "runtime")
        self._checks[check.id] = check
        return check

    def disable(self, check_id: str) -> bool:
        c = self._checks.get(check_id)
        if c:
            c.enabled = False
            return True
        return False

    def enable(self, check_id: str) -> bool:
        c = self._checks.get(check_id)
        if c:
            c.enabled = True
            return True
        return False

    def summary(self) -> dict:
        checks = self.all_checks()
        by_sev: dict[str, int] = {}
        for c in checks:
            key = c.severity.value if hasattr(c.severity, "value") else str(c.severity)
            by_sev[key] = by_sev.get(key, 0) + 1
        return {
            "total": len(checks),
            "by_severity": by_sev,
            "by_framework": {f: len(self.by_framework(f)) for f in self.frameworks()},
            "checks_dir": str(self.checks_dir),
        }


def _parse_check(raw: dict, framework: str, source_file: str) -> CheckDefinition:
    sev_str = raw.get("severity", "MEDIUM").upper()
    try:
        sev = Severity(sev_str)
    except ValueError:
        sev = Severity.MEDIUM
    return CheckDefinition(
        id=raw["id"],
        title=raw["title"],
        severity=sev,
        description=raw.get("description", "").strip(),
        cypher=raw.get("cypher", "").strip(),
        framework=framework,
        recommendation=raw.get("recommendation", "").strip(),
        mitre=raw.get("mitre", []),
        references=raw.get("references", []),
        enabled=raw.get("enabled", True),
        source_file=source_file,
    )


def _find_checks_dir() -> Path:
    """Locate the checks/ directory relative to the installed package or cwd."""
    # 1. IAMWATCHING_CHECKS_DIR environment variable override
    env_dir = os.environ.get("IAMWATCHING_CHECKS_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.exists():
            return p

    # 2. Relative to this file (iamwatching/patterns/registry.py)
    #    → go up two levels to project root → checks/
    pkg_parent = Path(__file__).parent.parent.parent
    candidate = pkg_parent / "checks"
    if candidate.exists():
        return candidate

    # 3. Current working directory
    cwd_candidate = Path.cwd() / "checks"
    if cwd_candidate.exists():
        return cwd_candidate

    # 4. Fallback: create in cwd
    log.warning("checks/ directory not found; defaulting to %s", cwd_candidate)
    cwd_candidate.mkdir(parents=True, exist_ok=True)
    (cwd_candidate / "builtin").mkdir(exist_ok=True)
    (cwd_candidate / "custom").mkdir(exist_ok=True)
    return cwd_candidate


# Module-level default registry instance
_default_registry: Optional[CheckRegistry] = None


def get_registry(checks_dir: Optional[Path] = None) -> CheckRegistry:
    """Get (or create) the default registry."""
    global _default_registry
    if _default_registry is None or checks_dir is not None:
        _default_registry = CheckRegistry(checks_dir)
    return _default_registry
