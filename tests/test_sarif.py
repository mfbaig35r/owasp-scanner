"""Tests for SARIF export."""

from __future__ import annotations

from owasp_scanner.core.database import Database
from owasp_scanner.core.sarif import generate_sarif


class TestSarif:
    def test_empty_findings(self):
        sarif = generate_sarif([])
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_finding_mapped_correctly(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py",
            line_number=10,
            rule_id="A05-001",
            owasp_category="A05",
            severity="critical",
            title="SQL injection",
            description="Bad query",
            suggested_fix="Use parameterized queries",
        )
        sarif = generate_sarif([f])
        results = sarif["runs"][0]["results"]
        assert len(results) == 1

        result = results[0]
        assert result["ruleId"] == "A05-001"
        assert result["level"] == "error"  # critical → error
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
        assert result["properties"]["owasp-category"] == "A05"
        assert result["fixes"][0]["description"]["text"] == "Use parameterized queries"

    def test_severity_mapping(self, tmp_db: Database):
        findings = []
        for sev, expected in [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
        ]:
            f, _ = tmp_db.create_finding(
                file_path="/app.py", owasp_category="A05",
                severity=sev, title=f"{sev} issue", description="D",
            )
            findings.append(f)

        sarif = generate_sarif(findings)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note"]

    def test_rules_in_tool_driver(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", rule_id="A05-001",
            owasp_category="A05", severity="high",
            title="T", description="D",
        )
        sarif = generate_sarif([f])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "A05-001" in rule_ids

    def test_schema_present(self):
        sarif = generate_sarif([])
        assert "$schema" in sarif
        assert "sarif" in sarif["$schema"]
