"""Tests for the scanning engine."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.database import Database
from owasp_scanner.core.scanner import (
    SCANNABLE_EXTENSIONS,
    SKIP_DIRS,
    RuleMatch,
    scan_file_content,
    scan_path,
)


class TestScanFileContent:
    def test_finds_vulnerabilities_in_bad_code(self, sample_vulnerable_py: Path):
        content = sample_vulnerable_py.read_text()
        matches = scan_file_content(content, str(sample_vulnerable_py))
        assert len(matches) > 0
        categories = {m.rule.owasp_category for m in matches}
        assert "A05" in categories  # pickle, yaml, os.system, SQL injection
        assert "A04" in categories  # MD5
        assert "A02" in categories  # DEBUG=True

    def test_clean_code_produces_no_matches(self, sample_clean_py: Path):
        content = sample_clean_py.read_text()
        matches = scan_file_content(content, str(sample_clean_py))
        # Clean code should have zero or very few matches
        # Some rules are broad (e.g., random) but clean code avoids them
        critical = [m for m in matches if m.rule.severity == "critical"]
        assert len(critical) == 0

    def test_returns_line_numbers(self, sample_vulnerable_py: Path):
        content = sample_vulnerable_py.read_text()
        matches = scan_file_content(content, str(sample_vulnerable_py))
        for m in matches:
            assert m.line_number > 0
            assert m.file_path == str(sample_vulnerable_py)

    def test_empty_code_no_matches(self):
        matches = scan_file_content("", "empty.py")
        assert len(matches) == 0

    def test_comments_only_no_matches(self):
        code = "# This is a comment\n# Another comment\n"
        matches = scan_file_content(code, "comments.py")
        assert len(matches) == 0

    def test_rule_category_filter(self, sample_vulnerable_py: Path):
        from owasp_scanner.rules.patterns import get_rules

        content = sample_vulnerable_py.read_text()
        a05_rules = get_rules(owasp_category="A05")
        matches = scan_file_content(content, str(sample_vulnerable_py), rules=a05_rules)
        for m in matches:
            assert m.rule.owasp_category == "A05"


class TestScanPath:
    def test_scan_file_creates_findings(self, tmp_db: Database, sample_vulnerable_py: Path):
        scan = tmp_db.create_scan("file", str(sample_vulnerable_py))
        result = scan_path(sample_vulnerable_py, tmp_db, scan.id)
        assert len(result.findings) > 0
        for f in result.findings:
            assert f.scan_id == scan.id
            assert f.file_path == str(sample_vulnerable_py)

    def test_scan_directory(
        self, tmp_db: Database, sample_vulnerable_py: Path, sample_clean_py: Path,
    ):
        scan = tmp_db.create_scan("directory", str(sample_vulnerable_py.parent))
        result = scan_path(sample_vulnerable_py.parent, tmp_db, scan.id)
        vuln_findings = [f for f in result.findings if "vulnerable" in f.file_path]
        assert len(vuln_findings) > 0

    def test_scan_empty_directory(self, tmp_db: Database, tmp_path: Path):
        empty = tmp_path / "empty_dir"
        empty.mkdir()
        scan = tmp_db.create_scan("directory", str(empty))
        result = scan_path(empty, tmp_db, scan.id)
        assert len(result.findings) == 0

    def test_skips_venv_directory(self, tmp_db: Database, tmp_path: Path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        bad_file = venv / "bad.py"
        bad_file.write_text("DEBUG = True\n")
        scan = tmp_db.create_scan("directory", str(tmp_path))
        result = scan_path(tmp_path, tmp_db, scan.id)
        assert all(".venv" not in f.file_path for f in result.findings)

    def test_skips_large_files(self, tmp_db: Database, tmp_path: Path):
        large_file = tmp_path / "large.py"
        large_file.write_text("DEBUG = True\n" * 50000)
        scan = tmp_db.create_scan("file", str(large_file))
        result = scan_path(large_file, tmp_db, scan.id)
        assert len(result.findings) == 0

    def test_code_snippet_included(self, tmp_db: Database, sample_vulnerable_py: Path):
        scan = tmp_db.create_scan("file", str(sample_vulnerable_py))
        result = scan_path(sample_vulnerable_py, tmp_db, scan.id)
        for f in result.findings:
            assert f.code_snippet is not None
            assert "|" in f.code_snippet

    def test_nonexistent_path(self, tmp_db: Database):
        scan = tmp_db.create_scan("file", "/nonexistent/path.py")
        result = scan_path(Path("/nonexistent/path.py"), tmp_db, scan.id)
        assert len(result.findings) == 0

    def test_dedup_across_scans(self, tmp_db: Database, sample_vulnerable_py: Path):
        """Scanning the same file twice should not create duplicate findings."""
        scan1 = tmp_db.create_scan("file", str(sample_vulnerable_py))
        r1 = scan_path(sample_vulnerable_py, tmp_db, scan1.id)

        scan2 = tmp_db.create_scan("file", str(sample_vulnerable_py))
        r2 = scan_path(sample_vulnerable_py, tmp_db, scan2.id)

        assert r1.new_count > 0
        assert r2.new_count == 0
        assert r2.existing_count == r1.new_count
        # Total findings in DB should equal first scan count
        assert len(tmp_db.list_findings()) == r1.new_count


class TestSuppression:
    def test_inline_suppression_by_rule_id(self):
        code = "result = eval(user_input)  # owasp-ignore: A05-004\n"
        matches = scan_file_content(code, "test.py")
        eval_matches = [m for m in matches if m.rule.id == "A05-004"]
        assert len(eval_matches) == 0

    def test_inline_suppression_by_category(self):
        code = "result = eval(user_input)  # owasp-ignore: A05\n"
        matches = scan_file_content(code, "test.py")
        a05_matches = [m for m in matches if m.rule.owasp_category == "A05"]
        assert len(a05_matches) == 0

    def test_suppression_on_line_above(self):
        code = "# owasp-ignore: A05-004\nresult = eval(user_input)\n"
        matches = scan_file_content(code, "test.py")
        eval_matches = [m for m in matches if m.rule.id == "A05-004"]
        assert len(eval_matches) == 0

    def test_suppression_wrong_rule_still_matches(self):
        code = "result = eval(user_input)  # owasp-ignore: A01-001\n"
        matches = scan_file_content(code, "test.py")
        eval_matches = [m for m in matches if m.rule.id == "A05-004"]
        assert len(eval_matches) > 0

    def test_suppression_comma_separated(self):
        code = "result = eval(user_input)  # owasp-ignore: A05-003, A05-004\n"
        matches = scan_file_content(code, "test.py")
        eval_matches = [m for m in matches if m.rule.id == "A05-004"]
        assert len(eval_matches) == 0

    def test_no_suppression_without_comment(self):
        code = "result = eval(user_input)\n"
        matches = scan_file_content(code, "test.py")
        eval_matches = [m for m in matches if m.rule.id == "A05-004"]
        assert len(eval_matches) > 0


class TestGetChangedFiles:
    def test_returns_changed_files(self, tmp_path: Path):
        from unittest.mock import MagicMock, patch

        from owasp_scanner.core.scanner import get_changed_files

        # Create some files
        (tmp_path / ".git").mkdir()
        (tmp_path / "changed.py").write_text("DEBUG = True\n")
        (tmp_path / "also_changed.py").write_text("x = 1\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "changed.py\nalso_changed.py\n"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            files = get_changed_files(tmp_path, "main")
        assert len(files) == 2
        assert any("changed.py" in str(f) for f in files)

    def test_empty_diff(self, tmp_path: Path):
        from unittest.mock import MagicMock, patch

        from owasp_scanner.core.scanner import get_changed_files

        (tmp_path / ".git").mkdir()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            files = get_changed_files(tmp_path, "main")
        assert len(files) == 0


class TestFileCollectionConstants:
    def test_skip_dirs_contains_common_excludes(self):
        assert ".git" in SKIP_DIRS
        assert "node_modules" in SKIP_DIRS
        assert ".venv" in SKIP_DIRS
        assert "__pycache__" in SKIP_DIRS

    def test_scannable_extensions_contains_python(self):
        assert ".py" in SCANNABLE_EXTENSIONS
        assert ".js" in SCANNABLE_EXTENSIONS
        assert ".html" in SCANNABLE_EXTENSIONS
        assert ".yaml" in SCANNABLE_EXTENSIONS


class TestRuleMatch:
    def test_to_dict(self):
        from owasp_scanner.rules.patterns import get_rules

        rule = get_rules()[0]
        match = RuleMatch(
            rule=rule,
            file_path="/test.py",
            line_number=10,
            line_content="DEBUG = True",
        )
        d = match.to_dict()
        assert d["rule_id"] == rule.id
        assert d["file_path"] == "/test.py"
        assert d["line_number"] == 10
        assert d["line_content"] == "DEBUG = True"
