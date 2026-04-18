"""Integration tests for MCP server tools."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from owasp_scanner.core.database import Database
from owasp_scanner.server import (
    analyze_code,
    create_baseline,
    create_finding,
    deep_analyze,
    export_report,
    export_sarif,
    get_finding,
    get_owasp_reference,
    get_summary,
    get_trends,
    health_check,
    list_findings,
    list_rules,
    list_scans,
    scan_config,
    scan_directory,
    scan_file,
    scan_pr,
    update_finding,
    verify_fix,
)


@pytest.fixture
def mock_db(tmp_db: Database):
    """Patch get_db to use temp database for all server tools."""
    with patch("owasp_scanner.server.get_db", return_value=tmp_db):
        yield tmp_db


class TestScanTools:
    async def test_scan_directory(self, mock_db: Database, sample_vulnerable_py: Path):
        result = await scan_directory(str(sample_vulnerable_py.parent))
        assert "scan_id" in result
        assert result["total_findings"] > 0
        assert "by_category" in result
        assert "by_severity" in result

    async def test_scan_directory_nonexistent(self, mock_db: Database):
        result = await scan_directory("/nonexistent/path")
        assert "error" in result

    async def test_scan_file(self, mock_db: Database, sample_vulnerable_py: Path):
        result = await scan_file(str(sample_vulnerable_py))
        assert "scan_id" in result
        assert result["total_findings"] > 0

    async def test_scan_file_not_a_file(self, mock_db: Database, tmp_path: Path):
        result = await scan_file(str(tmp_path))  # Directory, not file
        assert "error" in result

    async def test_analyze_code_no_persist(self, mock_db: Database):
        code = 'DEBUG = True\npassword = "secret123"'
        result = await analyze_code(code)
        assert result["total_findings"] > 0
        # Verify nothing was saved to DB
        findings = mock_db.list_findings()
        assert len(findings) == 0

    async def test_scan_config_django(
        self, mock_db: Database, tmp_path: Path,
    ):
        settings = tmp_path / "settings.py"
        settings.write_text(
            "DEBUG = True\n"
            "INSTALLED_APPS = ['django.contrib.admin']\n"
            "MIDDLEWARE = []\n"
            "ROOT_URLCONF = 'app.urls'\n"
            "DATABASES = {}\n"
        )
        result = await scan_config(str(settings))
        assert result["framework"] == "django"
        assert result["total_checks"] > 0
        titles = [c["title"] for c in result["checks"]]
        assert any("DEBUG" in t for t in titles)

    async def test_scan_config_not_a_file(self, mock_db: Database, tmp_path: Path):
        result = await scan_config(str(tmp_path))
        assert "error" in result

    async def test_analyze_code_filter_category(self, mock_db: Database):
        code = 'DEBUG = True\nhashlib.md5(x)'
        result = await analyze_code(code, owasp_category="A04")
        for f in result["findings"]:
            assert f["owasp_category"] == "A04"


class TestFindingsManagement:
    async def test_create_and_get_finding(self, mock_db: Database):
        result = await create_finding(
            file_path="/app.py",
            owasp_category="A01",
            severity="high",
            title="Missing authz",
            description="No authorization check on admin endpoint",
        )
        assert result["status"] == "created"
        finding_id = result["finding"]["id"]

        detail = await get_finding(finding_id)
        assert detail["title"] == "Missing authz"
        assert "audit_trail" in detail
        assert detail["owasp_label"] == "Broken Access Control"

    async def test_get_finding_not_found(self, mock_db: Database):
        result = await get_finding("nonexistent")
        assert "error" in result

    async def test_list_findings_empty(self, mock_db: Database):
        result = await list_findings()
        assert result["count"] == 0

    async def test_list_findings_with_filters(self, mock_db: Database):
        await create_finding(
            file_path="/a.py", owasp_category="A05",
            severity="critical", title="SQLi", description="D",
        )
        await create_finding(
            file_path="/b.py", owasp_category="A02",
            severity="medium", title="Debug", description="D",
        )
        critical = await list_findings(severity="critical")
        assert critical["count"] == 1

    async def test_update_finding_status(self, mock_db: Database):
        created = await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="Test", description="D",
        )
        finding_id = created["finding"]["id"]

        result = await update_finding(finding_id, status="fixed", notes="Patched in PR #42")
        assert result["status"] == "updated"
        assert result["finding"]["status"] == "fixed"
        assert result["finding"]["notes"] == "Patched in PR #42"

    async def test_update_finding_not_found(self, mock_db: Database):
        result = await update_finding("nonexistent", status="fixed")
        assert "error" in result


class TestVerifyFix:
    async def test_verify_fix_pattern_removed(
        self, mock_db: Database, tmp_path: Path,
    ):
        """Fix the code, verify_fix should auto-close the finding."""
        # Create a vulnerable file
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('DEBUG = True\n')

        # Scan it to create a finding
        result = await scan_file(str(vuln_file))
        assert result["total_findings"] > 0
        finding_id = result["findings"][0]["id"]

        # Fix the code
        vuln_file.write_text('DEBUG = False\n')

        # Verify the fix
        verify = await verify_fix(finding_id)
        assert verify["status"] == "verified_fixed"

        # Check finding is now fixed
        detail = await get_finding(finding_id)
        assert detail["status"] == "fixed"

    async def test_verify_fix_pattern_still_present(
        self, mock_db: Database, tmp_path: Path,
    ):
        """Don't fix the code, verify_fix should report still present."""
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('DEBUG = True\n')

        result = await scan_file(str(vuln_file))
        finding_id = result["findings"][0]["id"]

        # Don't fix — verify should say still present
        verify = await verify_fix(finding_id)
        assert verify["status"] == "still_present"
        assert "matches" in verify

    async def test_verify_fix_not_found(self, mock_db: Database):
        result = await verify_fix("nonexistent")
        assert "error" in result

    async def test_verify_fix_manual_finding(self, mock_db: Database):
        """Manual findings (no rule_id) can't be auto-verified."""
        created = await create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Manual", description="D",
        )
        finding_id = created["finding"]["id"]
        result = await verify_fix(finding_id)
        assert "error" in result
        assert "no rule_id" in result["error"]

    async def test_verify_fix_already_fixed(
        self, mock_db: Database, tmp_path: Path,
    ):
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('DEBUG = True\n')

        result = await scan_file(str(vuln_file))
        finding_id = result["findings"][0]["id"]
        await update_finding(finding_id, status="fixed")

        verify = await verify_fix(finding_id)
        assert verify["status"] == "already_resolved"

    async def test_verify_fix_file_deleted(
        self, mock_db: Database, tmp_path: Path,
    ):
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('DEBUG = True\n')

        result = await scan_file(str(vuln_file))
        finding_id = result["findings"][0]["id"]

        # Delete the file
        vuln_file.unlink()

        verify = await verify_fix(finding_id)
        assert verify["status"] == "file_missing"


class TestScanPr:
    async def test_scan_pr_not_a_repo(self, mock_db: Database, tmp_path: Path):
        result = await scan_pr(str(tmp_path))
        assert "error" in result

    async def test_scan_pr_returns_pass_field(
        self, mock_db: Database, tmp_path: Path,
    ):
        """scan_pr on a repo with no changes should pass."""
        from unittest.mock import patch as mock_patch

        (tmp_path / ".git").mkdir()
        with mock_patch(
            "owasp_scanner.core.scanner.get_changed_files",
            return_value=[],
        ):
            result = await scan_pr(str(tmp_path))
        # No changes = no findings = pass
        assert result.get("total_findings", 0) == 0


class TestDeepAnalyze:
    async def test_deep_analyze_fastapi_file(
        self, mock_db: Database, tmp_path: Path,
    ):
        code = '''
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return db.get(user_id)

@app.post("/login")
async def login(body: dict):
    return {"token": "abc"}
'''
        f = tmp_path / "main.py"
        f.write_text(code)
        result = await deep_analyze(str(f))
        assert result["framework"] == "fastapi"
        assert len(result["endpoints"]) > 0
        assert len(result["security_checklist"]) > 0
        assert "content" in result

    async def test_deep_analyze_returns_checklist(
        self, mock_db: Database, sample_vulnerable_py: Path,
    ):
        result = await deep_analyze(str(sample_vulnerable_py))
        checklist = result["security_checklist"]
        checks = [c["check"] for c in checklist]
        assert "Authorization" in checks
        assert "Rate Limiting" in checks
        assert "Input Validation" in checks

    async def test_deep_analyze_not_a_file(
        self, mock_db: Database, tmp_path: Path,
    ):
        result = await deep_analyze(str(tmp_path))
        assert "error" in result


class TestReporting:
    async def test_get_summary_empty(self, mock_db: Database):
        result = await get_summary()
        assert result["total_findings"] == 0

    async def test_get_summary_with_findings(self, mock_db: Database):
        await create_finding(
            file_path="/a.py", owasp_category="A05",
            severity="critical", title="T", description="D",
        )
        result = await get_summary()
        assert result["total_findings"] == 1
        assert result["by_status"]["open"] == 1

    async def test_list_scans_empty(self, mock_db: Database):
        result = await list_scans()
        assert result["count"] == 0


class TestExportSarif:
    async def test_export_sarif(self, mock_db: Database):
        await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="critical", title="T", description="D",
        )
        result = await export_sarif()
        assert "sarif" in result
        assert result["sarif"]["version"] == "2.1.0"
        assert result["findings_included"] == 1

    async def test_export_sarif_to_file(
        self, mock_db: Database, tmp_path: Path,
    ):
        await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="T", description="D",
        )
        out = tmp_path / "results.sarif"
        result = await export_sarif(output_path=str(out))
        assert out.exists()
        assert result["output_file"] == str(out)


class TestBaseline:
    async def test_create_baseline(self, mock_db: Database, tmp_path: Path):
        await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="T", description="D",
        )
        result = await create_baseline(str(tmp_path))
        assert result["findings_baselined"] >= 0
        assert (tmp_path / ".owasp-baseline.json").exists()

    async def test_create_baseline_not_a_dir(self, mock_db: Database):
        result = await create_baseline("/nonexistent/path")
        assert "error" in result


class TestTrends:
    async def test_get_trends_empty(self, mock_db: Database):
        result = await get_trends()
        assert result["opened_in_period"] == 0
        assert result["fixed_in_period"] == 0
        assert result["currently_open"] == 0
        assert result["mttr_hours"] is None

    async def test_get_trends_with_data(self, mock_db: Database):
        created = await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="T", description="D",
        )
        finding_id = created["finding"]["id"]
        await update_finding(finding_id, status="fixed")

        result = await get_trends()
        assert result["opened_in_period"] >= 1
        assert result["fixed_in_period"] >= 1
        assert result["mttr_hours"] is not None


class TestExportReport:
    async def test_export_report(self, mock_db: Database):
        await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="critical", title="SQLi", description="D",
        )
        result = await export_report()
        assert "report" in result
        assert "Security Scan Report" in result["report"]
        assert result["findings_included"] == 1

    async def test_export_report_to_file(
        self, mock_db: Database, tmp_path: Path,
    ):
        out = tmp_path / "report.md"
        await create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="T", description="D",
        )
        await export_report(output_path=str(out))
        assert out.exists()


class TestRulesAndReference:
    async def test_list_rules(self):
        result = await list_rules()
        assert result["count"] >= 25
        assert "owasp_categories" in result

    async def test_list_rules_filter(self):
        result = await list_rules(owasp_category="A05")
        for r in result["rules"]:
            assert r["owasp_category"] == "A05"

    async def test_get_owasp_reference_valid(self):
        result = await get_owasp_reference("A01")
        assert result["name"] == "Broken Access Control"
        assert result["rank"] == 1
        assert "key_defenses" in result
        assert "python_traps" in result

    async def test_get_owasp_reference_all_categories(self):
        for cat in [f"A{i:02d}" for i in range(1, 11)]:
            result = await get_owasp_reference(cat)
            assert "name" in result, f"Missing reference for {cat}"

    async def test_get_owasp_reference_invalid(self):
        result = await get_owasp_reference("A99")
        assert "error" in result


class TestDiagnostics:
    async def test_health_check(self, mock_db: Database):
        with patch("owasp_scanner.server.get_settings") as mock_settings:
            mock_settings.return_value.data_dir = Path("/tmp/test")
            mock_settings.return_value.db_path = Path("/tmp/test/scanner.db")
            result = await health_check()
            assert result["status"] == "healthy"
            assert result["total_rules"] >= 25
