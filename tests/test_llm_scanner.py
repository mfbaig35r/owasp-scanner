"""Tests for LLM-powered scanning. All API calls are mocked."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from owasp_scanner.core.database import Database
from owasp_scanner.core.llm_scanner import (
    LLMFinding,
    LLMUsage,
    _parse_scan_response,
    _slugify,
    is_available,
)

# ── Mock helpers ───────────────────────────────────────────────────────────


def _mock_completion(findings: list[dict]) -> MagicMock:
    """Build a mock OpenAI completion with function call response."""
    mock = MagicMock()
    mock.choices = [MagicMock()]
    mock.choices[0].message.function_call = MagicMock()
    mock.choices[0].message.function_call.name = "report_findings"
    mock.choices[0].message.function_call.arguments = json.dumps(
        {"findings": findings}
    )
    mock.usage = MagicMock(prompt_tokens=500, completion_tokens=200)
    return mock


def _mock_triage_completion(assessments: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.choices = [MagicMock()]
    mock.choices[0].message.function_call = MagicMock()
    mock.choices[0].message.function_call.name = "report_triage"
    mock.choices[0].message.function_call.arguments = json.dumps(
        {"assessments": assessments}
    )
    mock.usage = MagicMock(prompt_tokens=300, completion_tokens=150)
    return mock


# ── Availability ───────────────────────────────────────────────────────────


class TestIsAvailable:
    def test_not_available_no_sdk(self):
        with patch("owasp_scanner.core.llm_scanner._HAS_OPENAI", False):
            assert is_available() is False

    def test_not_available_no_key(self):
        with (
            patch("owasp_scanner.core.llm_scanner._HAS_OPENAI", True),
            patch("owasp_scanner.core.llm_scanner.get_settings") as mock_s,
        ):
            mock_s.return_value.openai_api_key = ""
            mock_s.return_value.llm_enabled = True
            assert is_available() is False

    def test_not_available_not_enabled(self):
        with (
            patch("owasp_scanner.core.llm_scanner._HAS_OPENAI", True),
            patch("owasp_scanner.core.llm_scanner.get_settings") as mock_s,
        ):
            mock_s.return_value.openai_api_key = "sk-test"
            mock_s.return_value.llm_enabled = False
            assert is_available() is False

    def test_available_when_configured(self):
        with (
            patch("owasp_scanner.core.llm_scanner._HAS_OPENAI", True),
            patch("owasp_scanner.core.llm_scanner.get_settings") as mock_s,
        ):
            mock_s.return_value.openai_api_key = "sk-test"
            mock_s.return_value.llm_enabled = True
            assert is_available() is True


# ── Scanning ───────────────────────────────────────────────────────────────


class TestScanFileLLM:
    def test_parses_findings(self):
        response = _mock_completion([
            {
                "owasp_category": "A05",
                "severity": "critical",
                "title": "SQL injection in user query",
                "description": "User input concatenated into SQL",
                "line_number": 42,
                "suggested_fix": "Use parameterized queries",
                "confidence": 0.95,
            },
        ])
        findings = _parse_scan_response(response, "/app.py")
        assert len(findings) == 1
        f = findings[0]
        assert f.owasp_category == "A05"
        assert f.severity == "critical"
        assert f.confidence == 0.95
        assert f.rule_id.startswith("llm-A05-")
        assert f.line_number == 42

    def test_empty_findings(self):
        response = _mock_completion([])
        findings = _parse_scan_response(response, "/app.py")
        assert len(findings) == 0

    def test_no_function_call(self):
        mock = MagicMock()
        mock.choices = [MagicMock()]
        mock.choices[0].message.function_call = None
        findings = _parse_scan_response(mock, "/app.py")
        assert len(findings) == 0

    def test_invalid_json(self):
        mock = MagicMock()
        mock.choices = [MagicMock()]
        mock.choices[0].message.function_call = MagicMock()
        mock.choices[0].message.function_call.arguments = "not json"
        findings = _parse_scan_response(mock, "/app.py")
        assert len(findings) == 0

    def test_multiple_findings(self):
        response = _mock_completion([
            {
                "owasp_category": "A01",
                "severity": "high",
                "title": "Missing auth check",
                "description": "D",
                "line_number": 10,
                "suggested_fix": "Add authz",
                "confidence": 0.8,
            },
            {
                "owasp_category": "A06",
                "severity": "medium",
                "title": "No rate limiting",
                "description": "D",
                "line_number": 20,
                "suggested_fix": "Add rate limit",
                "confidence": 0.6,
            },
        ])
        findings = _parse_scan_response(response, "/app.py")
        assert len(findings) == 2
        assert findings[0].rule_id != findings[1].rule_id

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    def test_scan_file_llm_full(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import scan_file_llm

        mock_client.return_value.chat.completions.create.return_value = (
            _mock_completion([{
                "owasp_category": "A05",
                "severity": "high",
                "title": "Eval usage",
                "description": "D",
                "line_number": 5,
                "suggested_fix": "Remove eval",
                "confidence": 0.9,
            }])
        )

        findings, usage = scan_file_llm("eval(x)", "/app.py")
        assert len(findings) == 1
        assert usage.input_tokens == 500
        assert usage.output_tokens == 200
        assert usage.model == "gpt-5.4-nano"


# ── Triage ─────────────────────────────────────────────────────────────────


class TestTriage:
    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    def test_triage_findings(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import triage_findings

        mock_client.return_value.chat.completions.create.return_value = (
            _mock_triage_completion([{
                "finding_id": "abc-123",
                "verdict": "false_positive",
                "confidence": 0.9,
                "reasoning": "This eval is in a test fixture",
            }])
        )

        results, usage = triage_findings([{
            "id": "abc-123",
            "title": "eval() usage",
            "description": "D",
            "file_path": "/test.py",
            "line_number": 5,
            "code_context": "# test\neval(x)",
        }])
        assert len(results) == 1
        assert results[0].verdict == "false_positive"
        assert results[0].confidence == 0.9


# ── Helpers ────────────────────────────────────────────────────────────────


class TestSlugify:
    def test_basic(self):
        assert _slugify("SQL injection in user query") == "sql-injection-in-user-query"

    def test_special_chars(self):
        assert _slugify("Missing auth! (critical)") == "missing-auth-critical"

    def test_truncation(self):
        long = "a" * 100
        assert len(_slugify(long)) <= 40


class TestLLMUsage:
    def test_cost_calculation(self):
        u = LLMUsage(input_tokens=1_000_000, output_tokens=100_000, model="gpt-5.4-nano")
        # $0.10/1M input + $0.40/1M output = $0.10 + $0.04 = $0.14
        assert abs(u.estimated_cost_usd - 0.14) < 0.01

    def test_to_dict(self):
        u = LLMUsage(input_tokens=500, output_tokens=200, model="gpt-5.4-nano")
        d = u.to_dict()
        assert d["input_tokens"] == 500
        assert d["model"] == "gpt-5.4-nano"
        assert "estimated_cost_usd" in d


class TestLLMFinding:
    def test_to_dict(self):
        f = LLMFinding(
            owasp_category="A05", severity="high",
            title="Test", description="D",
            line_number=10, suggested_fix="Fix",
            confidence=0.8, rule_id="llm-A05-test",
        )
        d = f.to_dict()
        assert d["rule_id"] == "llm-A05-test"
        assert d["confidence"] == 0.8


# ── Database Integration ──────────────────────────────────────────────────


class TestConfidenceInDB:
    def test_confidence_persisted(self, tmp_db: Database):
        finding, is_new = tmp_db.create_finding(
            file_path="/app.py",
            owasp_category="A05",
            severity="high",
            title="LLM finding",
            description="D",
            rule_id="llm-A05-test",
            confidence=0.85,
        )
        assert is_new
        assert finding.confidence == 0.85

        retrieved = tmp_db.get_finding(finding.id)
        assert retrieved.confidence == 0.85

    def test_regex_finding_no_confidence(self, tmp_db: Database):
        finding, _ = tmp_db.create_finding(
            file_path="/app.py",
            owasp_category="A05",
            severity="high",
            title="Regex finding",
            description="D",
        )
        assert finding.confidence is None

    def test_confidence_in_to_dict(self, tmp_db: Database):
        finding, _ = tmp_db.create_finding(
            file_path="/app.py",
            owasp_category="A05",
            severity="high",
            title="T",
            description="D",
            confidence=0.7,
        )
        d = finding.to_dict()
        assert d["confidence"] == 0.7


# ── Mode Validation ───────────────────────────────────────────────────────


class TestModeValidation:
    async def test_invalid_mode(self, patched_db):
        from owasp_scanner.server import scan_directory

        result = await scan_directory("/tmp", mode="invalid")
        assert "error" in result
        assert "Invalid mode" in result["error"]

    async def test_llm_mode_not_available(self, patched_db):
        from owasp_scanner.server import scan_directory

        with patch(
            "owasp_scanner.core.llm_scanner.is_available",
            return_value=False,
        ):
            result = await scan_directory("/tmp", mode="llm")
            assert "error" in result
            assert "LLM" in result["error"]
