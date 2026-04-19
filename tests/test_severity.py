"""Tests for context-sensitive severity adjustment."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.rules.severity import adjust_severity, detect_network_surface


class TestAdjustSeverity:
    def test_test_file_reduces_severity(self):
        assert adjust_severity("critical", "tests/test_views.py") == "high"
        assert adjust_severity("high", "test_utils.py") == "medium"
        assert adjust_severity("medium", "/app/tests/test_api.py") == "low"
        assert adjust_severity("low", "tests/test_x.py") == "low"  # Can't go below low

    def test_test_suffix_reduces(self):
        assert adjust_severity("critical", "views_test.py") == "high"

    def test_conftest_reduces(self):
        assert adjust_severity("high", "tests/conftest.py") == "medium"

    def test_fixtures_reduces(self):
        assert adjust_severity("high", "fixtures/sample_data.py") == "medium"

    def test_migration_reduces_to_low(self):
        assert adjust_severity("critical", "migrations/0001_initial.py") == "low"
        assert adjust_severity("high", "app/migrations/0042.py") == "low"

    def test_alembic_reduces_to_low(self):
        assert adjust_severity("critical", "alembic/versions/abc123.py") == "low"

    def test_normal_file_unchanged(self):
        assert adjust_severity("critical", "app/views.py") == "critical"
        assert adjust_severity("high", "api/handlers.py") == "high"
        assert adjust_severity("medium", "models.py") == "medium"

    def test_unknown_severity_passthrough(self):
        assert adjust_severity("unknown", "app.py") == "unknown"


class TestNetworkSurfaceDetection:
    def test_local_project_no_frameworks(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("import sys\nprint('hello')")
        assert detect_network_surface(tmp_path) == "local"

    def test_fastapi_detected_as_network(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("from fastapi import FastAPI")
        assert detect_network_surface(tmp_path) == "network"

    def test_flask_detected_as_network(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("from flask import Flask")
        assert detect_network_surface(tmp_path) == "network"

    def test_mcp_server_detected_as_network(self, tmp_path: Path):
        (tmp_path / "server.py").write_text("from fastmcp import FastMCP")
        assert detect_network_surface(tmp_path) == "network"

    def test_django_detected_as_network(self, tmp_path: Path):
        (tmp_path / "settings.py").write_text("import django")
        assert detect_network_surface(tmp_path) == "network"

    def test_uvicorn_detected_as_network(self, tmp_path: Path):
        (tmp_path / "run.py").write_text("import uvicorn")
        assert detect_network_surface(tmp_path) == "network"

    def test_skips_venv_directories(self, tmp_path: Path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "flask_dep.py").write_text("from flask import Flask")
        (tmp_path / "main.py").write_text("print('cli tool')")
        assert detect_network_surface(tmp_path) == "local"

    def test_empty_project(self, tmp_path: Path):
        assert detect_network_surface(tmp_path) == "local"


class TestProjectSurfaceAdjustment:
    def test_local_reduces_severity(self):
        assert adjust_severity("critical", "app.py", project_surface="local") == "high"
        assert adjust_severity("high", "app.py", project_surface="local") == "medium"
        assert adjust_severity("medium", "app.py", project_surface="local") == "low"
        assert adjust_severity("low", "app.py", project_surface="local") == "low"

    def test_local_stacks_with_test_file(self):
        result = adjust_severity("critical", "tests/test_main.py", project_surface="local")
        assert result == "medium"  # test file: -1, local: -1 = -2
        result = adjust_severity("high", "tests/test_main.py", project_surface="local")
        assert result == "low"

    def test_network_no_change(self):
        assert adjust_severity("high", "app.py", project_surface="network") == "high"

    def test_none_surface_no_change(self):
        assert adjust_severity("high", "app.py", project_surface=None) == "high"

    def test_migration_in_local_stays_low(self):
        assert adjust_severity("critical", "migrations/0001.py", project_surface="local") == "low"
