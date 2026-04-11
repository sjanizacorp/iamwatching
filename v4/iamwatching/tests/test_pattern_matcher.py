"""
Pattern matcher tests.
No Neo4j or cloud SDK imports at module level.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from iamwatching.patterns.matcher import (
    PatternMatcher,
    Finding,
    Severity,
    RULES,
)


# ── Rule definitions ──────────────────────────────────────────────────────────

class TestRuleDefinitions:

    def test_all_rules_have_seven_fields(self):
        for rule in RULES:
            assert len(rule) == 7, f"Rule {rule[0]} has {len(rule)} fields, expected 7"

    def test_all_rule_ids_unique(self):
        ids = [r[0] for r in RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_rules_have_required_fields(self):
        for rule in RULES:
            rule_id, title, severity, description, cypher, recommendation, mitre = rule
            assert rule_id,       f"Empty rule_id in {rule}"
            assert title,         f"Empty title in {rule_id}"
            assert isinstance(severity, Severity), f"{rule_id}: severity must be Severity enum"
            assert cypher.strip(), f"{rule_id}: empty cypher"
            assert recommendation, f"{rule_id}: empty recommendation"
            assert isinstance(mitre, list), f"{rule_id}: mitre must be list"

    def test_at_least_four_critical_rules(self):
        critical = [r for r in RULES if r[2] == Severity.CRITICAL]
        assert len(critical) >= 4, f"Only {len(critical)} CRITICAL rules, expected >= 4"

    def test_all_cloud_namespaces_present(self):
        rule_ids = [r[0] for r in RULES]
        assert any(rid.startswith("AWS-") for rid in rule_ids), "No AWS- rules"
        assert any(rid.startswith("AZ-")  for rid in rule_ids), "No AZ- rules"
        assert any(rid.startswith("GCP-") for rid in rule_ids), "No GCP- rules"
        assert any(rid.startswith("XC-")  for rid in rule_ids), "No XC- rules"

    def test_cross_cloud_rule_exists(self):
        xc = [r for r in RULES if r[0].startswith("XC-")]
        assert len(xc) >= 1

    def test_severity_enum_values(self):
        severities = {r[2] for r in RULES}
        # Should span multiple severity levels
        assert len(severities) >= 3

    def test_all_cyphers_contain_match_or_merge(self):
        for rule in RULES:
            cypher = rule[4].upper()
            assert "MATCH" in cypher or "MERGE" in cypher, \
                f"Rule {rule[0]} cypher has no MATCH/MERGE"

    def test_all_mitre_lists_nonempty(self):
        for rule in RULES:
            assert len(rule[6]) >= 1, f"Rule {rule[0]} has empty MITRE list"

    def test_all_mitre_entries_start_with_T(self):
        for rule in RULES:
            for entry in rule[6]:
                assert entry.startswith("T"), f"Rule {rule[0]} MITRE entry '{entry}' should start with T"


# ── Severity enum ─────────────────────────────────────────────────────────────

class TestSeverityEnum:

    def test_all_severities_defined(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        actual   = {s.value for s in Severity}
        assert expected == actual

    def test_string_comparison(self):
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH     == "HIGH"


# ── Finding dataclass ─────────────────────────────────────────────────────────

class TestFindingDataclass:

    def test_finding_defaults(self):
        f = Finding(
            rule_id="AWS-001",
            title="Test",
            severity=Severity.HIGH,
            description="desc",
        )
        assert f.affected_nodes == []
        assert f.recommendation == ""
        assert f.mitre_attack   == []
        assert f.raw_records    == []

    def test_finding_with_records(self):
        f = Finding(
            rule_id="AWS-001",
            title="Test",
            severity=Severity.CRITICAL,
            description="desc",
            affected_nodes=[{"arn": "arn:aws:iam::123:role/admin"}],
            recommendation="Fix it",
            mitre_attack=["T1078.004"],
        )
        assert len(f.affected_nodes) == 1
        assert f.mitre_attack == ["T1078.004"]


# ── PatternMatcher with mocked Neo4j ─────────────────────────────────────────

@pytest.mark.asyncio
class TestPatternMatcherWithMockNeo4j:

    def _make_matcher_with_mock_driver(self, query_results=None):
        """Build a PatternMatcher whose _run_query is mocked."""
        matcher = PatternMatcher("bolt://localhost:7687", "neo4j", "test")
        matcher._run_query = AsyncMock(return_value=query_results or [])
        return matcher

    async def test_run_rule_returns_finding(self):
        matcher = self._make_matcher_with_mock_driver(
            query_results=[{"principal": "arn:aws:iam::123:role/admin", "type": "Role"}]
        )
        rule    = RULES[0]
        finding = await matcher.run_rule(rule)

        assert isinstance(finding, Finding)
        assert finding.rule_id   == rule[0]
        assert finding.severity  == rule[2]
        assert len(finding.affected_nodes) == 1

    async def test_run_all_returns_only_findings_with_results(self):
        """run_all filters out rules with no affected nodes."""
        matcher = self._make_matcher_with_mock_driver(query_results=[])
        findings = await matcher.run_all()
        # All queries return empty → no findings
        assert findings == []

    async def test_run_all_with_findings(self):
        """When queries return rows, findings are included and sorted by severity.

        use_registry=False so the test covers only the hardcoded RULES tuples —
        the YAML registry is tested separately and adds additional checks at runtime.
        """
        matcher = self._make_matcher_with_mock_driver(
            query_results=[{"node": "something"}]
        )
        # use_registry=False: test only hardcoded RULES, not YAML registry checks
        findings = await matcher.run_all(use_registry=False)
        assert len(findings) == len(RULES), (
            f"Expected {len(RULES)} findings (one per hardcoded rule), got {len(findings)}. "
            "If RULES changed, update this assertion."
        )

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for i in range(len(findings) - 1):
            a_sev = findings[i].severity
            b_sev = findings[i + 1].severity
            a = severity_order.index(a_sev.value if hasattr(a_sev, "value") else a_sev)
            b = severity_order.index(b_sev.value if hasattr(b_sev, "value") else b_sev)
            assert a <= b, f"Findings not sorted at index {i}: {a_sev} > {b_sev}"

    async def test_run_all_severity_filter_critical(self):
        matcher  = self._make_matcher_with_mock_driver(
            query_results=[{"node": "hit"}]
        )
        findings = await matcher.run_all(severity_filter=Severity.CRITICAL)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    async def test_run_custom_query(self):
        matcher = self._make_matcher_with_mock_driver(
            query_results=[{"n": "test_node"}]
        )
        finding = await matcher.run_custom("MATCH (n) RETURN n LIMIT 1", title="Custom")
        assert finding.rule_id == "CUSTOM"
        assert finding.title   == "Custom"
        assert finding.raw_records == [{"n": "test_node"}]

    async def test_run_rule_handles_query_exception(self):
        """A failing Cypher query should not crash run_rule, just log and return empty."""
        matcher = PatternMatcher("bolt://localhost:7687", "neo4j", "test")
        matcher._run_query = AsyncMock(side_effect=Exception("Neo4j unavailable"))

        rule    = RULES[0]
        finding = await matcher.run_rule(rule)
        # Should return a Finding with an error record, not raise
        assert isinstance(finding, Finding)
        assert finding.rule_id == rule[0]
        assert any("error" in str(r).lower() for r in finding.raw_records)


# ─────────────────────────────────────────────────────────────────────────────
# Check Registry tests (YAML-based checks)
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckRegistry:
    """Tests for the YAML check registry (CIS, OWASP, NIST, custom checks)."""

    def _get_registry(self):
        from iamwatching.patterns.registry import CheckRegistry  # noqa: PLC0415
        from pathlib import Path
        # Locate the checks/ directory relative to this test file
        checks_dir = Path(__file__).parent.parent / "checks"
        if not checks_dir.exists():
            pytest.skip(f"checks/ directory not found at {checks_dir}")
        return CheckRegistry(checks_dir)

    def test_registry_loads_checks(self):
        r = self._get_registry()
        n = r.load()
        assert n > 0, "Registry should load at least 1 check"

    def test_cis_checks_present(self):
        r = self._get_registry()
        r.load()
        cis = r.by_framework("CIS-AWS-3.0")
        assert len(cis) >= 5, f"Expected >=5 CIS checks, got {len(cis)}"

    def test_owasp_checks_present(self):
        r = self._get_registry()
        r.load()
        owasp = r.by_framework("OWASP-CLOUD-NATIVE-2024")
        assert len(owasp) >= 4, f"Expected >=4 OWASP checks, got {len(owasp)}"

    def test_nist_checks_present(self):
        r = self._get_registry()
        r.load()
        nist = r.by_framework("NIST-800-53-R5")
        assert len(nist) >= 3, f"Expected >=3 NIST checks, got {len(nist)}"

    def test_checks_have_valid_severity(self):
        r = self._get_registry()
        r.load()
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for c in r.all_checks():
            assert c.severity.value in valid, f"{c.id} has invalid severity {c.severity}"

    def test_checks_have_cypher(self):
        r = self._get_registry()
        r.load()
        for c in r.all_checks():
            assert c.cypher.strip(), f"{c.id} has empty cypher query"
            assert "MATCH" in c.cypher.upper() or "RETURN" in c.cypher.upper(),                 f"{c.id} cypher doesn't look like Cypher: {c.cypher[:50]}"

    def test_get_specific_check(self):
        r = self._get_registry()
        r.load()
        c = r.get("CIS-AWS-1.4")
        assert c is not None, "CIS-AWS-1.4 should exist"
        assert c.severity.value == "CRITICAL"
        assert c.framework == "CIS-AWS-3.0"
        assert c.recommendation

    def test_disable_enable(self):
        r = self._get_registry()
        r.load()
        check_id = "CIS-AWS-1.17"
        assert r.disable(check_id) is True
        assert not r.get(check_id).enabled
        # Should not appear in enabled-only list
        enabled_ids = [c.id for c in r.all_checks(enabled_only=True)]
        assert check_id not in enabled_ids
        # Re-enable
        assert r.enable(check_id) is True
        assert r.get(check_id).enabled

    def test_summary_has_correct_keys(self):
        r = self._get_registry()
        r.load()
        s = r.summary()
        assert "total" in s
        assert "by_severity" in s
        assert "by_framework" in s
        assert s["total"] > 0
        # Severity keys should be clean strings, not "Severity.CRITICAL"
        for key in s["by_severity"]:
            assert "." not in key, f"Severity key should not contain dot: {key}"

    def test_sorted_by_severity(self):
        r = self._get_registry()
        r.load()
        checks = r.all_checks()
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for i in range(len(checks) - 1):
            a = order.index(checks[i].severity.value)
            b = order.index(checks[i + 1].severity.value)
            assert a <= b, f"Sort wrong: {checks[i].id}({checks[i].severity.value}) before {checks[i+1].id}({checks[i+1].severity.value})"

    def test_custom_check_overrides_builtin(self):
        """Custom check with same ID as builtin replaces it."""
        from iamwatching.patterns.registry import CheckRegistry, _parse_check  # noqa: PLC0415
        from iamwatching.patterns.matcher import Severity  # noqa: PLC0415
        from pathlib import Path

        checks_dir = Path(__file__).parent.parent / "checks"
        if not checks_dir.exists():
            pytest.skip("checks/ directory not found")

        r = CheckRegistry(checks_dir)
        r.load()
        original = r.get("CIS-AWS-1.4")
        assert original is not None

        # Add custom check with same ID — should override
        custom_data = {
            "id": "CIS-AWS-1.4",
            "title": "Custom Override Title",
            "severity": "HIGH",
            "description": "custom",
            "cypher": "MATCH (n) RETURN n LIMIT 1",
        }
        r.add_custom(custom_data, framework="CUSTOM")
        overridden = r.get("CIS-AWS-1.4")
        assert overridden.title == "Custom Override Title"
        assert overridden.severity == Severity.HIGH
