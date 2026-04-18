"""Tests for pip-audit integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from owasp_scanner.core.pip_audit import (
    DependencySource,
    VulnerabilityResult,
    run_pip_audit,
)


def _mock_pip_audit_output(deps: list[dict]) -> MagicMock:
    """Create a mock subprocess result with pip-audit JSON output."""
    mock = MagicMock()
    mock.returncode = 1 if any(d.get("vulns") for d in deps) else 0
    mock.stdout = json.dumps({"dependencies": deps})
    mock.stderr = ""
    return mock


class TestRunPipAudit:
    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=[])
    def test_pip_audit_not_installed(self, mock_cmd, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\n")
        with pytest.raises(FileNotFoundError, match="not installed"):
            run_pip_audit(req)

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_no_vulnerabilities(self, mock_run, mock_cmd, tmp_path: Path):
        mock_run.return_value = _mock_pip_audit_output([
            {"name": "flask", "version": "3.0.0", "vulns": []},
        ])
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.0.0\n")
        results, source = run_pip_audit(req)
        assert len(results) == 0
        assert source.source_type == "requirements"

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_found_vulnerabilities(self, mock_run, mock_cmd, tmp_path: Path):
        mock_run.return_value = _mock_pip_audit_output([
            {
                "name": "flask",
                "version": "2.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-12345",
                        "description": "XSS vulnerability in Flask",
                        "fix_versions": ["2.3.3", "3.0.0"],
                    },
                ],
            },
            {"name": "requests", "version": "2.31.0", "vulns": []},
        ])
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\nrequests==2.31.0\n")
        results, source = run_pip_audit(req)
        assert len(results) == 1
        assert results[0].package == "flask"
        assert results[0].vuln_id == "CVE-2023-12345"
        assert "2.3.3" in results[0].fix_versions

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_multiple_vulns_same_package(
        self, mock_run, mock_cmd, tmp_path: Path,
    ):
        mock_run.return_value = _mock_pip_audit_output([
            {
                "name": "django",
                "version": "3.2.0",
                "vulns": [
                    {"id": "CVE-2023-001", "description": "Bug 1", "fix_versions": ["3.2.1"]},
                    {"id": "CVE-2023-002", "description": "Bug 2", "fix_versions": ["3.2.2"]},
                ],
            },
        ])
        req = tmp_path / "requirements.txt"
        req.write_text("django==3.2.0\n")
        results, _ = run_pip_audit(req)
        assert len(results) == 2

    def test_directory_without_dependencies(self, tmp_path: Path):
        with patch(
            "owasp_scanner.core.pip_audit._get_pip_audit_cmd",
            return_value=["pip-audit"],
        ):
            with pytest.raises(FileNotFoundError, match="No dependency files"):
                run_pip_audit(tmp_path)

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_directory_finds_requirements(
        self, mock_run, mock_cmd, tmp_path: Path,
    ):
        mock_run.return_value = _mock_pip_audit_output([])
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.0.0\n")
        results, source = run_pip_audit(tmp_path)
        assert len(results) == 0
        assert source.path == req
        assert source.source_type == "requirements"

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_pip_audit_crash(self, mock_run, mock_cmd, tmp_path: Path):
        mock = MagicMock()
        mock.returncode = 2
        mock.stderr = "some internal error"
        mock.stdout = ""
        mock_run.return_value = mock
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.0.0\n")
        with pytest.raises(RuntimeError, match="pip-audit failed"):
            run_pip_audit(req)


class TestDependencySourceDetection:
    def test_finds_pyproject(self, tmp_path: Path):
        from owasp_scanner.core.pip_audit import _find_dependency_source

        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
        source = _find_dependency_source(tmp_path)
        assert source is not None
        assert source.source_type == "pyproject"

    def test_finds_uv_lock(self, tmp_path: Path):
        from owasp_scanner.core.pip_audit import _find_dependency_source

        (tmp_path / "uv.lock").write_text("# lock\n")
        source = _find_dependency_source(tmp_path)
        assert source is not None
        assert source.source_type == "lockfile"

    def test_finds_poetry_lock(self, tmp_path: Path):
        from owasp_scanner.core.pip_audit import _find_dependency_source

        (tmp_path / "poetry.lock").write_text("# lock\n")
        source = _find_dependency_source(tmp_path)
        assert source is not None
        assert source.source_type == "lockfile"

    def test_requirements_takes_priority(self, tmp_path: Path):
        from owasp_scanner.core.pip_audit import _find_dependency_source

        (tmp_path / "requirements.txt").write_text("flask==3.0\n")
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        source = _find_dependency_source(tmp_path)
        assert source.source_type == "requirements"

    def test_nothing_found(self, tmp_path: Path):
        from owasp_scanner.core.pip_audit import _find_dependency_source

        source = _find_dependency_source(tmp_path)
        assert source is None

    def test_pyproject_audit_args(self):
        source = DependencySource(Path("/project/pyproject.toml"), "pyproject")
        assert source.pip_audit_args == ["--path", "/project"]

    def test_requirements_audit_args(self):
        source = DependencySource(Path("/project/requirements.txt"), "requirements")
        assert source.pip_audit_args == ["--requirement", "/project/requirements.txt"]

    @patch("owasp_scanner.core.pip_audit._get_pip_audit_cmd", return_value=["pip-audit"])
    @patch("subprocess.run")
    def test_pyproject_direct_path(self, mock_run, mock_cmd, tmp_path: Path):
        """Passing pyproject.toml directly should work."""
        mock_run.return_value = _mock_pip_audit_output([])
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\n")
        results, source = run_pip_audit(pyproject)
        assert source.source_type == "pyproject"
        # Verify --path was used, not --requirement
        call_args = mock_run.call_args[0][0]
        assert "--path" in call_args


class TestVulnerabilityResult:
    def test_to_dict(self):
        v = VulnerabilityResult(
            package="flask",
            installed_version="2.0.0",
            vuln_id="CVE-2023-12345",
            description="XSS vulnerability",
            fix_versions=["2.3.3"],
        )
        d = v.to_dict()
        assert d["package"] == "flask"
        assert d["vuln_id"] == "CVE-2023-12345"
        assert d["fix_versions"] == ["2.3.3"]
