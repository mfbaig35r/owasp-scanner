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


def _finding(fid: str, title: str = "eval() usage") -> dict:
    return {
        "id": fid,
        "title": title,
        "description": "D",
        "file_path": "/test.py",
        "line_number": 5,
        "code_context": "# test\neval(x)",
    }


class TestTriage:
    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_single(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import triage_findings

        mock_client.return_value.chat.completions.create.return_value = (
            _mock_triage_completion([{
                "finding_id": "abc-123",
                "verdict": "false_positive",
                "confidence": 0.9,
                "reasoning": "This eval is in a test fixture",
            }])
        )

        results, usage = await triage_findings([_finding("abc-123")])
        assert len(results) == 1
        assert results[0].verdict == "false_positive"
        assert results[0].confidence == 0.9
        assert usage.input_tokens == 300
        assert usage.output_tokens == 150

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_per_finding_calls(self, mock_model, mock_client):
        """Each finding triggers its own OpenAI call (not a single batched one)."""
        from owasp_scanner.core.llm_scanner import triage_findings

        # Side effect returns a verdict echoing the finding_id from the prompt.
        # Since each call is independent, we just return a fixed verdict per call.
        completions = [
            _mock_triage_completion([{
                "finding_id": fid,
                "verdict": "true_positive",
                "confidence": 0.7,
                "reasoning": "r",
            }])
            for fid in ("a", "b", "c")
        ]
        mock_client.return_value.chat.completions.create.side_effect = completions

        results, usage = await triage_findings(
            [_finding("a"), _finding("b"), _finding("c")],
            max_concurrency=2,
        )
        assert len(results) == 3
        assert {r.finding_id for r in results} == {"a", "b", "c"}
        # One call per finding
        assert mock_client.return_value.chat.completions.create.call_count == 3
        # Usage is aggregated across calls
        assert usage.input_tokens == 300 * 3
        assert usage.output_tokens == 150 * 3

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_one_failure_does_not_abort(self, mock_model, mock_client):
        """A single failing call yields needs_investigation; others succeed."""
        from owasp_scanner.core.llm_scanner import triage_findings

        good = _mock_triage_completion([{
            "finding_id": "good",
            "verdict": "true_positive",
            "confidence": 0.8,
            "reasoning": "r",
        }])
        mock_client.return_value.chat.completions.create.side_effect = [
            good,
            RuntimeError("transient API error"),
            good,
        ]

        results, _ = await triage_findings(
            [_finding("good"), _finding("bad"), _finding("good")],
            max_concurrency=1,  # serialize so side_effect order is deterministic
        )
        assert len(results) == 3
        assert results[0].verdict == "true_positive"
        assert results[1].verdict == "needs_investigation"
        assert "transient API error" in results[1].reasoning
        assert results[2].verdict == "true_positive"

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_per_call_timeout(self, mock_model, mock_client):
        """A call exceeding per_call_timeout yields needs_investigation."""
        import time

        from owasp_scanner.core.llm_scanner import triage_findings

        def slow(*args, **kwargs):
            time.sleep(0.5)
            return _mock_triage_completion([])

        mock_client.return_value.chat.completions.create.side_effect = slow

        results, _ = await triage_findings(
            [_finding("slow")],
            per_call_timeout=0.05,
        )
        assert len(results) == 1
        assert results[0].verdict == "needs_investigation"
        assert "timed out" in results[0].reasoning.lower()

    async def test_triage_findings_empty_input(self):
        from owasp_scanner.core.llm_scanner import triage_findings

        results, usage = await triage_findings([])
        assert results == []
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_passes_project_context(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import triage_findings

        mock_client.return_value.chat.completions.create.return_value = (
            _mock_triage_completion([{
                "finding_id": "x",
                "verdict": "false_positive",
                "confidence": 0.9,
                "reasoning": "context says so",
            }])
        )

        ctx = "Auth model: every API route gates with `tenant_id` BEFORE helpers."
        await triage_findings([_finding("x")], project_context=ctx)

        call = mock_client.return_value.chat.completions.create.call_args
        user_msg = call.kwargs["messages"][1]["content"]
        assert "Project context" in user_msg
        assert ctx in user_msg

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    async def test_triage_findings_no_context_no_header(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import triage_findings

        mock_client.return_value.chat.completions.create.return_value = (
            _mock_triage_completion([{
                "finding_id": "x",
                "verdict": "true_positive",
                "confidence": 0.8,
                "reasoning": "r",
            }])
        )

        await triage_findings([_finding("x")])
        user_msg = mock_client.return_value.chat.completions.create.call_args.kwargs[
            "messages"
        ][1]["content"]
        assert "Project context" not in user_msg


class TestProjectContextPrompt:
    def test_python_builder_no_context(self):
        from owasp_scanner.core.prompts import build_python_file_context

        msg = build_python_file_context("/app.py", "x = 1")
        assert "Project context" not in msg

    def test_python_builder_with_context(self):
        from owasp_scanner.core.prompts import build_python_file_context

        msg = build_python_file_context(
            "/app.py", "x = 1", project_context="Tenant gate is at API layer.",
        )
        assert "Project context" in msg
        assert "Tenant gate is at API layer." in msg
        # Context should appear before the file content
        assert msg.index("Tenant gate") < msg.index("File: /app.py")

    def test_nextjs_builder_with_context(self):
        from owasp_scanner.core.prompts import build_nextjs_file_context

        msg = build_nextjs_file_context(
            "/route.ts", "route_handler", "export async function GET() {}",
            project_context="All routes pass through auth middleware.",
        )
        assert "Project context" in msg
        assert "All routes pass through auth middleware." in msg

    def test_empty_string_treated_as_no_context(self):
        from owasp_scanner.core.prompts import build_python_file_context

        msg = build_python_file_context("/app.py", "x = 1", project_context="   \n  ")
        assert "Project context" not in msg

    @patch("owasp_scanner.core.llm_scanner._get_client")
    @patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano")
    def test_scan_file_llm_passes_context(self, mock_model, mock_client):
        from owasp_scanner.core.llm_scanner import scan_file_llm

        mock_client.return_value.chat.completions.create.return_value = _mock_completion([])
        scan_file_llm(
            "x = 1", "/app.py",
            project_type="python",
            project_context="Internal helpers trust their callers.",
        )
        user_msg = mock_client.return_value.chat.completions.create.call_args.kwargs[
            "messages"
        ][1]["content"]
        assert "Internal helpers trust their callers." in user_msg
        assert "Project context" in user_msg


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
