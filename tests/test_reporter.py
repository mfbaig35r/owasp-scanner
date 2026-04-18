"""Tests for markdown report generation."""

from __future__ import annotations

from owasp_scanner.core.database import Database, Finding
from owasp_scanner.core.reporter import _fmt_ts, generate_report


class TestGenerateReport:
    def _make_findings(self, db: Database) -> list[Finding]:
        findings = []
        for i, (cat, sev) in enumerate([
            ("A05", "critical"),
            ("A05", "high"),
            ("A02", "medium"),
            ("A10", "low"),
        ]):
            f, _ = db.create_finding(
                file_path=f"/app/file{i}.py",
                line_number=i * 10 + 1,
                owasp_category=cat,
                severity=sev,
                title=f"Finding {i}",
                description=f"Description for finding {i}",
                suggested_fix=f"Fix for finding {i}",
            )
            findings.append(f)
        return findings

    def test_empty_report(self):
        report = generate_report([])
        assert "No security findings" in report

    def test_report_has_sections(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        assert "# Security Scan Report" in report
        assert "## Executive Summary" in report
        assert "## Findings Detail" in report
        assert "## Remediation Priority" in report

    def test_report_counts(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        assert "**Total findings:** 4" in report
        assert "**Open:** 4" in report

    def test_report_severity_table(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        assert "CRITICAL" in report
        assert "HIGH" in report

    def test_report_category_table(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        assert "Injection" in report  # A05 label
        assert "Security Misconfiguration" in report  # A02 label

    def test_report_findings_ordered_by_severity(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        # Critical should appear before Low
        crit_pos = report.index("CRITICAL")
        low_pos = report.index("LOW")
        assert crit_pos < low_pos

    def test_report_fixed_findings_not_in_detail(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="critical", title="Fixed Issue",
            description="This was fixed",
        )
        tmp_db.update_finding(f.id, status="fixed")
        findings = tmp_db.list_findings()
        report = generate_report(findings)
        # Fixed findings counted but not in detail section
        assert "**Fixed:** 1" in report

    def test_report_top_files(self, tmp_db: Database):
        for i in range(5):
            tmp_db.create_finding(
                file_path="/app/views.py", owasp_category="A05",
                severity="high", title=f"Issue {i}",
                description="D", line_number=i,
            )
        findings = [f for f in tmp_db.list_findings()]
        report = generate_report(findings)
        assert "`/app/views.py`" in report
        assert "5" in report  # Count for this file

    def test_report_has_metadata_header(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        scans = [tmp_db.create_scan("directory", "/repo")]
        report = generate_report(findings, scans=scans)
        assert "**Generated:**" in report
        assert "**Scan history:**" in report

    def test_report_findings_have_timestamps(self, tmp_db: Database):
        findings = self._make_findings(tmp_db)
        report = generate_report(findings)
        assert "**Found:**" in report
        assert "UTC" in report

    def test_report_triaged_has_timestamp(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="Triaged Issue",
            description="D",
        )
        tmp_db.update_finding(
            f.id, status="false_positive",
            notes="Test fixture, not real",
        )
        findings = tmp_db.list_findings()
        report = generate_report(findings)
        assert "*Triaged:*" in report
        assert "UTC" in report


class TestFormatTimestamp:
    def test_valid_iso(self):
        assert _fmt_ts("2026-04-17T00:53:00+00:00") == "2026-04-17 00:53 UTC"

    def test_none(self):
        assert _fmt_ts(None) == ""

    def test_empty(self):
        assert _fmt_ts("") == ""

    def test_garbage_passthrough(self):
        assert _fmt_ts("not-a-date") == "not-a-date"
