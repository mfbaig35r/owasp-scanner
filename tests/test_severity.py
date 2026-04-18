"""Tests for context-sensitive severity adjustment."""

from __future__ import annotations

from owasp_scanner.rules.severity import adjust_severity


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
