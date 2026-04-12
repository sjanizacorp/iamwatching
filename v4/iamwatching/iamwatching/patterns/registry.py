"""
Check Registry — IamWatching v2.0
===================================
Loads, validates, and manages detection checks from YAML files.
Supports built-in checks, custom checks, and runtime import/export.

Directory layout:
  checks/
    builtin/          Built-in checks (one file per framework family)
      cis_aws.yaml
      owasp_cloud.yaml
      nist_csf.yaml
      pci_dss.yaml
      iso27001.yaml
      aws_compute_security.yaml
      aws_data_security.yaml
      azure_security.yaml
      gcp_security.yaml
      cross_cloud_normalization.yaml
    custom/           User checks — never overwritten by updates
      *.yaml
    .disabled         JSON file tracking which check IDs are disabled (persisted)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from iamwatching.patterns.matcher import Severity, Finding

log = logging.getLogger(__name__)

# ── Public sources for each framework family ──────────────────────────────────
# These are the canonical GitHub raw URLs for each built-in check file.
# `iamwatching checks update` fetches these and replaces the local builtin files.
BUILTIN_SOURCES: dict[str, str] = {
    "cis_aws.yaml":                  "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/cis_aws.yaml",
    "owasp_cloud.yaml":              "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/owasp_cloud.yaml",
    "nist_csf.yaml":                 "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/nist_csf.yaml",
    "pci_dss.yaml":                  "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/pci_dss.yaml",
    "iso27001.yaml":                 "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/iso27001.yaml",
    "aws_compute_security.yaml":     "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/aws_compute_security.yaml",
    "aws_data_security.yaml":        "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/aws_data_security.yaml",
    "azure_security.yaml":           "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/azure_security.yaml",
    "gcp_security.yaml":             "https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/gcp_security.yaml",
    "cross_cloud_normalization.yaml":"https://raw.githubusercontent.com/anizacorp/iamwatching/main/checks/builtin/cross_cloud_normalization.yaml",
}


# ── Data model ────────────────────────────────────────────────────────────────

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

    def to_dict(self) -> dict:
        """Serialise to a plain dict (for JSON/YAML export)."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "description": self.description,
            "cypher": self.cypher,
            "framework": self.framework,
            "recommendation": self.recommendation,
            "mitre": self.mitre,
            "references": self.references,
            "enabled": self.enabled,
        }


# ── Registry ──────────────────────────────────────────────────────────────────

class CheckRegistry:
    """
    Loads and manages all check definitions.
    Custom checks with the same ID override built-ins.
    Disabled state is persisted in checks/.disabled (JSON).
    """

    def __init__(self, checks_dir: Optional[Path] = None):
        self.checks_dir = checks_dir or _find_checks_dir()
        self._checks: dict[str, CheckDefinition] = {}
        self._loaded = False

    # ── Loading ───────────────────────────────────────────────────────────────

    def load(self, force: bool = False) -> int:
        """Load all checks from YAML files. Returns total count."""
        if self._loaded and not force:
            return len(self._checks)
        self._checks.clear()

        for yaml_file in sorted((self.checks_dir / "builtin").glob("*.yaml")):
            self._load_file(yaml_file)
        custom_dir = self.checks_dir / "custom"
        if custom_dir.exists():
            for yaml_file in sorted(custom_dir.glob("*.yaml")):
                self._load_file(yaml_file)

        # Apply persisted disabled state
        for cid in self._load_disabled_set():
            if cid in self._checks:
                self._checks[cid].enabled = False

        self._loaded = True
        log.info("CheckRegistry: loaded %d checks from %s", len(self._checks), self.checks_dir)
        return len(self._checks)

    def _load_file(self, path: Path) -> int:
        count = 0
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not data or "checks" not in data:
                return 0
            framework = data.get("framework", path.stem)
            for raw in data.get("checks", []):
                try:
                    check = _parse_check(raw, framework, str(path))
                    if check.id in self._checks:
                        log.debug("Check %s overrides previous definition", check.id)
                    self._checks[check.id] = check
                    count += 1
                except Exception as e:
                    log.warning("Skipping malformed check in %s: %s", path.name, e)
        except Exception as e:
            log.error("Failed to load %s: %s", path, e)
        return count

    # ── Queries ───────────────────────────────────────────────────────────────

    def all_checks(self, enabled_only: bool = True) -> list[CheckDefinition]:
        if not self._loaded:
            self.load()
        checks = list(self._checks.values())
        if enabled_only:
            checks = [c for c in checks if c.enabled]
        return sorted(checks, key=lambda c: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(
                c.severity.value if hasattr(c.severity, "value") else str(c.severity)
            ),
            c.id,
        ))

    def get(self, check_id: str) -> Optional[CheckDefinition]:
        if not self._loaded:
            self.load()
        return self._checks.get(check_id)

    def by_framework(self, framework: str) -> list[CheckDefinition]:
        return [c for c in self.all_checks(enabled_only=False) if c.framework == framework]

    def frameworks(self) -> list[str]:
        return sorted({c.framework for c in self.all_checks(enabled_only=False)})

    def summary(self) -> dict:
        checks = self.all_checks(enabled_only=False)
        by_sev: dict[str, int] = {}
        for c in checks:
            key = c.severity.value if hasattr(c.severity, "value") else str(c.severity)
            by_sev[key] = by_sev.get(key, 0) + 1
        return {
            "total": len(checks),
            "enabled": sum(1 for c in checks if c.enabled),
            "disabled": sum(1 for c in checks if not c.enabled),
            "by_severity": by_sev,
            "by_framework": {f: len(self.by_framework(f)) for f in self.frameworks()},
            "checks_dir": str(self.checks_dir),
        }

    # ── Enable / Disable (persisted) ─────────────────────────────────────────

    def disable(self, check_id: str) -> bool:
        c = self._checks.get(check_id)
        if not c:
            return False
        c.enabled = False
        self._save_disabled_set(self._disabled_ids())
        return True

    def enable(self, check_id: str) -> bool:
        c = self._checks.get(check_id)
        if not c:
            return False
        c.enabled = True
        self._save_disabled_set(self._disabled_ids())
        return True

    def _disabled_ids(self) -> set[str]:
        return {cid for cid, c in self._checks.items() if not c.enabled}

    def _disabled_file(self) -> Path:
        return self.checks_dir / ".disabled"

    def _load_disabled_set(self) -> set[str]:
        f = self._disabled_file()
        if f.exists():
            try:
                return set(json.loads(f.read_text()))
            except Exception:
                pass
        return set()

    def _save_disabled_set(self, ids: set[str]) -> None:
        try:
            self._disabled_file().write_text(json.dumps(sorted(ids), indent=2))
        except Exception as e:
            log.warning("Could not persist disabled state: %s", e)

    # ── Add / Write custom checks ─────────────────────────────────────────────

    def add_custom(
        self,
        check_def: dict,
        framework: str = "CUSTOM",
        filename: str = "custom_runtime.yaml",
        persist: bool = False,
    ) -> CheckDefinition:
        """
        Add a check definition. If persist=True, saves it to checks/custom/.
        """
        effective_framework = check_def.get("framework", framework)
        check = _parse_check(check_def, effective_framework, "runtime")
        self._checks[check.id] = check

        if persist:
            custom_dir = self.checks_dir / "custom"
            custom_dir.mkdir(parents=True, exist_ok=True)
            safe_name = check.id.lower().replace("-", "_") + ".yaml"
            out_path = custom_dir / safe_name
            self._write_check_to_yaml(check, out_path)
            log.info("Custom check %s saved to %s", check.id, out_path)

        return check

    def delete_custom(self, check_id: str) -> bool:
        """Delete a custom check from memory and disk."""
        check = self._checks.get(check_id)
        if not check:
            return False
        # Only allow deleting checks from the custom directory
        if "custom" not in check.source_file and check.source_file != "runtime":
            raise ValueError(f"Cannot delete built-in check {check_id}. Use disable instead.")
        del self._checks[check_id]
        # Remove file if it's the only check in it
        if check.source_file and check.source_file != "runtime":
            src = Path(check.source_file)
            if src.exists():
                try:
                    data = yaml.safe_load(src.read_text())
                    remaining = [c for c in data.get("checks", []) if c["id"] != check_id]
                    if remaining:
                        data["checks"] = remaining
                        src.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True))
                    else:
                        src.unlink()
                except Exception as e:
                    log.warning("Could not remove check from file %s: %s", src, e)
        return True

    def _write_check_to_yaml(self, check: CheckDefinition, path: Path) -> None:
        """Write a single check to its own YAML file."""
        sev = check.severity.value if hasattr(check.severity, "value") else str(check.severity)
        data = {
            "framework": check.framework,
            "description": f"Custom check: {check.title}",
            "checks": [{
                "id": check.id,
                "title": check.title,
                "severity": sev,
                "description": check.description,
                "cypher": check.cypher,
                "recommendation": check.recommendation,
                "mitre": check.mitre,
                "references": check.references,
                "enabled": check.enabled,
            }],
        }
        path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False))

    # ── Export ────────────────────────────────────────────────────────────────

    def export_yaml(
        self,
        output_path: str | Path,
        framework: Optional[str] = None,
        custom_only: bool = False,
        enabled_only: bool = False,
    ) -> int:
        """
        Export checks to a YAML file.
        Returns number of checks written.
        """
        checks = self.all_checks(enabled_only=enabled_only)
        if framework:
            checks = [c for c in checks if framework.upper() in c.framework.upper()]
        if custom_only:
            checks = [c for c in checks if "custom" in c.source_file.lower() or c.source_file == "runtime"]

        # Group by framework for clean output
        by_fw: dict[str, list] = {}
        for c in checks:
            by_fw.setdefault(c.framework, []).append(c.to_dict())

        sections = []
        for fw, fw_checks in sorted(by_fw.items()):
            sections.append({
                "framework": fw,
                "description": f"Exported from IamWatching — {fw}",
                "checks": fw_checks,
            })

        output_path = Path(output_path)
        output_path.write_text(
            yaml.dump(
                {"exports": sections} if len(sections) > 1 else sections[0],
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        )
        return len(checks)

    def export_json(
        self,
        output_path: str | Path,
        framework: Optional[str] = None,
        custom_only: bool = False,
        enabled_only: bool = False,
    ) -> int:
        """Export checks to a JSON file. Returns number of checks written."""
        checks = self.all_checks(enabled_only=enabled_only)
        if framework:
            checks = [c for c in checks if framework.upper() in c.framework.upper()]
        if custom_only:
            checks = [c for c in checks if "custom" in c.source_file.lower() or c.source_file == "runtime"]

        export_data = {
            "iamwatching_checks_export": True,
            "version": "2.0.0",
            "count": len(checks),
            "checks": [c.to_dict() for c in checks],
        }
        Path(output_path).write_text(json.dumps(export_data, indent=2, default=str))
        return len(checks)

    # ── Import ────────────────────────────────────────────────────────────────

    def import_file(
        self,
        input_path: str | Path,
        target: str = "custom",
        overwrite: bool = False,
    ) -> tuple[int, list[str]]:
        """
        Import checks from a YAML or JSON file.

        Args:
            input_path: Path to .yaml or .json file.
            target: 'custom' saves to checks/custom/; 'builtin' to checks/builtin/.
            overwrite: If False, skip checks whose ID already exists.

        Returns:
            (count_imported, list_of_skipped_ids)
        """
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Import file not found: {path}")

        # Parse
        raw_text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            data = json.loads(raw_text)
            # Normalise JSON export format
            if "checks" in data:
                raw_checks = data["checks"]
                framework  = data.get("framework", "CUSTOM")
            elif "exports" in data:
                raw_checks = [c for section in data["exports"] for c in section.get("checks", [])]
                framework  = "CUSTOM"
            else:
                raw_checks = data if isinstance(data, list) else []
                framework  = "CUSTOM"
        else:
            data = yaml.safe_load(raw_text)
            if "exports" in data:
                # Multi-framework export
                raw_checks = []
                for section in data["exports"]:
                    fw = section.get("framework", "CUSTOM")
                    for c in section.get("checks", []):
                        c.setdefault("framework", fw)
                        raw_checks.append(c)
                framework = "CUSTOM"
            elif "checks" in data:
                framework  = data.get("framework", "CUSTOM")
                raw_checks = data["checks"]
            else:
                raw_checks = [data] if "id" in data else []
                framework  = "CUSTOM"

        target_dir = self.checks_dir / target
        target_dir.mkdir(parents=True, exist_ok=True)

        imported: list[CheckDefinition] = []
        skipped: list[str] = []

        for raw in raw_checks:
            cid = raw.get("id", "")
            if not cid:
                continue
            if not overwrite and cid in self._checks:
                skipped.append(cid)
                continue
            try:
                fw = raw.get("framework", framework)
                check = _parse_check(raw, fw, "import")
                self._checks[check.id] = check
                imported.append(check)
            except Exception as e:
                log.warning("Skipping malformed check %s: %s", cid, e)
                skipped.append(cid)

        # Persist imported checks to the target directory
        if imported:
            # Group by framework for clean file organisation
            by_fw: dict[str, list[CheckDefinition]] = {}
            for c in imported:
                by_fw.setdefault(c.framework, []).append(c)

            source_stem = path.stem.replace("-", "_").lower()
            for fw, fw_checks in by_fw.items():
                fw_slug = fw.lower().replace("-", "_").replace(".", "_")
                out_name = f"{source_stem}_{fw_slug}.yaml" if len(by_fw) > 1 else f"{source_stem}.yaml"
                out_path = target_dir / out_name
                # Merge with existing file if it exists
                existing: list[dict] = []
                if out_path.exists():
                    try:
                        ex = yaml.safe_load(out_path.read_text())
                        existing = ex.get("checks", [])
                        ex_ids = {c["id"] for c in existing}
                        existing = [c for c in existing if c["id"] not in {ch.id for ch in fw_checks}]
                    except Exception:
                        pass

                file_data = {
                    "framework": fw,
                    "description": f"Imported from {path.name}",
                    "checks": existing + [c.to_dict() for c in fw_checks],
                }
                out_path.write_text(
                    yaml.dump(file_data, default_flow_style=False, allow_unicode=True, sort_keys=False)
                )
                log.info("Imported %d checks to %s", len(fw_checks), out_path)

        return len(imported), skipped

    # ── Online update ─────────────────────────────────────────────────────────

    def update_builtin(
        self,
        families: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> dict[str, str]:
        """
        Download the latest built-in check files from GitHub and replace local copies.

        Args:
            families: List of filenames to update (e.g. ['cis_aws.yaml']).
                      If None, updates all families.
            dry_run: If True, only checks what would be updated without writing files.

        Returns:
            Dict mapping filename → status ('updated', 'unchanged', 'failed', 'would_update')
        """
        import urllib.request  # noqa: PLC0415
        import urllib.error    # noqa: PLC0415

        builtin_dir = self.checks_dir / "builtin"
        builtin_dir.mkdir(parents=True, exist_ok=True)

        sources = {k: v for k, v in BUILTIN_SOURCES.items()
                   if not families or k in families}

        results: dict[str, str] = {}

        for filename, url in sources.items():
            local_path = builtin_dir / filename
            try:
                with urllib.request.urlopen(url, timeout=15) as resp:
                    remote_content = resp.read().decode("utf-8")

                # Validate it's actually a valid check file
                parsed = yaml.safe_load(remote_content)
                if not parsed or "checks" not in parsed:
                    results[filename] = "failed: remote file has no 'checks' key"
                    continue

                remote_count = len(parsed["checks"])

                if local_path.exists():
                    local_content = local_path.read_text(encoding="utf-8")
                    if local_content.strip() == remote_content.strip():
                        results[filename] = f"unchanged ({remote_count} checks)"
                        continue

                if dry_run:
                    local_count = 0
                    if local_path.exists():
                        try:
                            local_count = len(yaml.safe_load(local_path.read_text()).get("checks", []))
                        except Exception:
                            pass
                    results[filename] = f"would_update (local={local_count} → remote={remote_count} checks)"
                else:
                    # Back up existing file
                    if local_path.exists():
                        backup = local_path.with_suffix(".yaml.bak")
                        backup.write_text(local_path.read_text(encoding="utf-8"))
                    local_path.write_text(remote_content, encoding="utf-8")
                    results[filename] = f"updated ({remote_count} checks)"
                    log.info("Updated %s: %d checks from %s", filename, remote_count, url)

            except urllib.error.URLError as e:
                results[filename] = f"failed: network error — {e}"
                log.warning("Could not fetch %s: %s", url, e)
            except Exception as e:
                results[filename] = f"failed: {e}"
                log.warning("Update failed for %s: %s", filename, e)

        # Reload registry after successful updates
        if not dry_run and any("updated" in v for v in results.values()):
            self.load(force=True)

        return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_check(raw: dict, framework: str, source_file: str) -> CheckDefinition:
    sev_str = str(raw.get("severity", "MEDIUM")).upper()
    try:
        sev = Severity(sev_str)
    except ValueError:
        sev = Severity.MEDIUM
    return CheckDefinition(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=sev,
        description=str(raw.get("description", "")).strip(),
        cypher=str(raw.get("cypher", "")).strip(),
        framework=str(raw.get("framework", framework)),
        recommendation=str(raw.get("recommendation", "")).strip(),
        mitre=list(raw.get("mitre", [])),
        references=list(raw.get("references", [])),
        enabled=bool(raw.get("enabled", True)),
        source_file=source_file,
    )


def _find_checks_dir() -> Path:
    env_dir = os.environ.get("IAMWATCHING_CHECKS_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.exists():
            return p
    pkg_parent = Path(__file__).parent.parent.parent
    candidate = pkg_parent / "checks"
    if candidate.exists():
        return candidate
    cwd_candidate = Path.cwd() / "checks"
    if cwd_candidate.exists():
        return cwd_candidate
    log.warning("checks/ not found; creating at %s", cwd_candidate)
    (cwd_candidate / "builtin").mkdir(parents=True, exist_ok=True)
    (cwd_candidate / "custom").mkdir(exist_ok=True)
    return cwd_candidate


_default_registry: Optional[CheckRegistry] = None


def get_registry(checks_dir: Optional[Path] = None) -> CheckRegistry:
    global _default_registry
    if _default_registry is None or checks_dir is not None:
        _default_registry = CheckRegistry(checks_dir)
    return _default_registry
