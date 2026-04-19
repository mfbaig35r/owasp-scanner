"""Integration tests for test quality scanning."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.database import Database


class TestScanTestQuality:
    async def test_scan_finds_test_gaps(self, patched_db, tmp_path: Path):
        from owasp_scanner.server import scan_test_quality

        (tmp_path / "pyproject.toml").write_text("[project]\n")
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_empty.py").write_text("def test_nothing():\n    pass\n")
        (tmp_path / "utils.py").write_text("def add(a, b): return a + b\n")

        result = await scan_test_quality(str(tmp_path))
        assert result.get("total_findings", 0) > 0

    async def test_findings_have_test_quality_category_type(
        self, patched_db, tmp_path: Path,
    ):
        from owasp_scanner.server import scan_test_quality

        (tmp_path / "pyproject.toml").write_text("[project]\n")
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_empty.py").write_text("def test_nothing():\n    pass\n")

        result = await scan_test_quality(str(tmp_path))
        for f in result.get("findings", []):
            assert f.get("category_type") == "test_quality"

    async def test_scan_not_a_directory(self, patched_db, tmp_path: Path):
        from owasp_scanner.server import scan_test_quality

        result = await scan_test_quality(str(tmp_path / "nonexistent"))
        assert "error" in result


class TestCategoryTypeInDB:
    def test_create_finding_with_test_quality(self, tmp_db: Database):
        finding, is_new = tmp_db.create_finding(
            file_path="/tests/test_app.py",
            owasp_category="TQ02",
            severity="high",
            title="Test has no assert",
            description="D",
            category_type="test_quality",
        )
        assert is_new
        assert finding.category_type == "test_quality"

    def test_default_category_type_is_security(self, tmp_db: Database):
        finding, _ = tmp_db.create_finding(
            file_path="/app.py",
            owasp_category="A05",
            severity="high",
            title="SQL injection",
            description="D",
        )
        assert finding.category_type == "security"

    def test_list_findings_filter_by_category_type(self, tmp_db: Database):
        tmp_db.create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="Security", description="D",
            category_type="security",
        )
        tmp_db.create_finding(
            file_path="/tests/test_app.py", owasp_category="TQ02",
            severity="medium", title="Test gap", description="D",
            category_type="test_quality",
        )

        security = tmp_db.list_findings(category_type="security")
        assert len(security) == 1
        assert security[0].category_type == "security"

        tq = tmp_db.list_findings(category_type="test_quality")
        assert len(tq) == 1
        assert tq[0].category_type == "test_quality"

        all_f = tmp_db.list_findings()
        assert len(all_f) == 2

    def test_category_type_in_to_dict(self, tmp_db: Database):
        finding, _ = tmp_db.create_finding(
            file_path="/t.py", owasp_category="TQ01",
            severity="high", title="T", description="D",
            category_type="test_quality",
        )
        d = finding.to_dict()
        assert d["category_type"] == "test_quality"
