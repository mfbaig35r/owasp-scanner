"""Integration tests for Next.js scanning."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from owasp_scanner.core.database import Database
from owasp_scanner.core.scanner import scan_path


class TestNextjsProjectScan:
    def test_scan_finds_nextjs_rules(
        self, tmp_db: Database, sample_nextjs_app: Path,
    ):
        """Scanning a Next.js project should find JS- prefixed findings."""
        scan = tmp_db.create_scan("directory", str(sample_nextjs_app))
        result = scan_path(sample_nextjs_app, tmp_db, scan.id)
        rule_ids = {f.rule_id for f in result.findings if f.rule_id}
        js_rules = {rid for rid in rule_ids if rid and rid.startswith("JS-")}
        assert len(js_rules) > 0, (
            f"Expected JS- rules in findings, got rule_ids: {rule_ids}"
        )

    def test_scan_finds_mass_assignment(
        self, tmp_db: Database, sample_nextjs_app: Path,
    ):
        """actions.ts has Object.fromEntries(formData) — should be flagged."""
        scan = tmp_db.create_scan("directory", str(sample_nextjs_app))
        result = scan_path(sample_nextjs_app, tmp_db, scan.id)
        mass_assign = [
            f for f in result.findings
            if f.rule_id and "A01-003" in f.rule_id
        ]
        assert len(mass_assign) > 0

    def test_scan_finds_prisma_raw(
        self, tmp_db: Database, sample_nextjs_app: Path,
    ):
        """route.ts has $queryRawUnsafe — should be flagged."""
        scan = tmp_db.create_scan("directory", str(sample_nextjs_app))
        result = scan_path(sample_nextjs_app, tmp_db, scan.id)
        prisma = [
            f for f in result.findings
            if f.rule_id and "A05-004" in f.rule_id
        ]
        assert len(prisma) > 0

    def test_scan_finds_env_secret(
        self, tmp_db: Database, sample_nextjs_app: Path,
    ):
        """NEXT_PUBLIC_SECRET_KEY in .env should be flagged."""
        scan = tmp_db.create_scan("directory", str(sample_nextjs_app))
        result = scan_path(sample_nextjs_app, tmp_db, scan.id)
        env_secrets = [
            f for f in result.findings
            if f.rule_id and "A02-001" in f.rule_id
        ]
        assert len(env_secrets) > 0

    def test_scan_finds_server_action(
        self, tmp_db: Database, sample_nextjs_app: Path,
    ):
        """actions.ts with 'use server' should be flagged."""
        scan = tmp_db.create_scan("directory", str(sample_nextjs_app))
        result = scan_path(sample_nextjs_app, tmp_db, scan.id)
        actions = [
            f for f in result.findings
            if f.rule_id and "A01-002" in f.rule_id
        ]
        assert len(actions) > 0


class TestProjectTypeDetection:
    async def test_scan_directory_detects_nextjs(
        self, patched_db, sample_nextjs_app: Path,
    ):
        from owasp_scanner.server import scan_directory

        result = await scan_directory(str(sample_nextjs_app))
        assert result.get("project_type") == "nextjs"

    async def test_scan_directory_detects_python(
        self, patched_db, tmp_path: Path,
    ):
        from owasp_scanner.server import scan_directory

        (tmp_path / "pyproject.toml").write_text("[project]")
        (tmp_path / "app.py").write_text("DEBUG = True\n")
        result = await scan_directory(str(tmp_path))
        assert result.get("project_type") == "python"


class TestLLMPromptSelection:
    def test_nextjs_prompt_used_for_nextjs_project(self):
        """Verify scan_file_llm uses Next.js prompt when project_type='nextjs'."""
        from unittest.mock import MagicMock

        from owasp_scanner.core.llm_scanner import scan_file_llm

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.function_call = MagicMock()
        mock_response.choices[0].message.function_call.arguments = '{"findings": []}'
        mock_response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        mock_client.chat.completions.create.return_value = mock_response

        with (
            patch("owasp_scanner.core.llm_scanner._get_client", return_value=mock_client),
            patch("owasp_scanner.core.llm_scanner._get_model", return_value="gpt-5.4-nano"),
        ):
            scan_file_llm(
                "export async function GET() {}",
                "app/api/users/route.ts",
                project_type="nextjs",
                file_type="route_handler",
            )

        # Check the system prompt used
        call_args = mock_client.chat.completions.create.call_args
        messages = call_args.kwargs.get("messages") or call_args[1].get("messages")
        system_msg = messages[0]["content"]
        assert "App Router" in system_msg or "SERVER ACTIONS" in system_msg

        # Check user message includes file type context
        user_msg = messages[1]["content"]
        assert "ROUTE HANDLER" in user_msg
