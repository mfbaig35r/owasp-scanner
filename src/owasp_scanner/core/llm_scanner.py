"""LLM-powered security scanning using OpenAI-compatible APIs.

Wraps the OpenAI SDK to scan code for OWASP Top 10 vulnerabilities
and triage regex findings. Supports any OpenAI-compatible API via
base_url override.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from owasp_scanner.core.config import get_settings
from owasp_scanner.core.prompts import (
    NEXTJS_SCAN_SYSTEM_PROMPT,
    SCAN_FUNCTION_SCHEMA,
    SCAN_SYSTEM_PROMPT,
    TRIAGE_FUNCTION_SCHEMA,
    TRIAGE_SYSTEM_PROMPT,
    build_nextjs_file_context,
    build_python_file_context,
)

try:
    import openai

    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False

logger = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────


@dataclass
class LLMFinding:
    """A security finding returned by the LLM."""
    owasp_category: str
    severity: str
    title: str
    description: str
    line_number: int | None
    suggested_fix: str
    confidence: float
    rule_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "line_number": self.line_number,
            "suggested_fix": self.suggested_fix,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
        }


@dataclass
class TriageResult:
    """LLM triage assessment of a regex finding."""
    finding_id: str
    verdict: str  # true_positive, false_positive, needs_investigation
    confidence: float
    reasoning: str
    adjusted_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "adjusted_severity": self.adjusted_severity,
        }


@dataclass
class LLMUsage:
    """Token usage and cost tracking for an LLM call."""
    input_tokens: int
    output_tokens: int
    model: str

    @property
    def estimated_cost_usd(self) -> float:
        # GPT-5.4-nano pricing estimate: ~$0.10/1M input, $0.40/1M output
        return (self.input_tokens * 0.10 + self.output_tokens * 0.40) / 1_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "model": self.model,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
        }


# ── Client management ─────────────────────────────────────────────────────


def is_available() -> bool:
    """Check if LLM scanning is available."""
    if not _HAS_OPENAI:
        return False
    settings = get_settings()
    return bool(settings.openai_api_key) and settings.llm_enabled


def _get_client() -> Any:
    """Get configured OpenAI client."""
    if not _HAS_OPENAI:
        raise RuntimeError(
            "openai SDK not installed. Install with: pip install owasp-scanner[llm]"
        )
    settings = get_settings()
    if not settings.openai_api_key:
        raise RuntimeError("OWASP_OPENAI_API_KEY not set.")
    if not settings.llm_enabled:
        raise RuntimeError("LLM scanning not enabled. Set OWASP_LLM_ENABLED=true.")

    kwargs: dict[str, Any] = {"api_key": settings.openai_api_key}
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url
    return openai.OpenAI(**kwargs)


def _get_model() -> str:
    return get_settings().llm_model


def _slugify(text: str) -> str:
    """Convert title to a URL-safe slug for rule IDs."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40]


def _extract_usage(response: Any) -> LLMUsage:
    """Extract token usage from an OpenAI response."""
    usage = response.usage
    return LLMUsage(
        input_tokens=usage.prompt_tokens if usage else 0,
        output_tokens=usage.completion_tokens if usage else 0,
        model=_get_model(),
    )


# ── Scanning ───────────────────────────────────────────────────────────────


def scan_file_llm(
    content: str,
    file_path: str,
    project_type: str = "python",
    file_type: str | None = None,
    project_context: str | None = None,
) -> tuple[list[LLMFinding], LLMUsage]:
    """Scan a file for security issues using the LLM.

    Args:
        content: File content to scan.
        file_path: Path to the file (for context).
        project_type: 'python', 'nextjs', or 'react' — selects system prompt.
        file_type: Next.js file type for context block (server_component, etc).
        project_context: Reviewer-supplied project context (auth model, trust
            boundaries, intentional design decisions). Prepended to the user
            message. Use to suppress false positives that need cross-module
            knowledge the LLM can't infer from a single file.

    Returns (findings, usage).
    """
    client = _get_client()
    model = _get_model()

    # Select system prompt based on project type
    system_prompt = (
        NEXTJS_SCAN_SYSTEM_PROMPT
        if project_type in ("nextjs", "react")
        else SCAN_SYSTEM_PROMPT
    )

    # Build user message with framework context
    if project_type in ("nextjs", "react") and file_type:
        user_content = build_nextjs_file_context(
            file_path, file_type, content, project_context=project_context,
        )
    else:
        user_content = build_python_file_context(
            file_path, content, project_context=project_context,
        )

    # Truncate very large files
    if len(content) > 150_000:
        content = content[:150_000] + "\n\n... [truncated — file too large for full analysis]"

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        functions=[SCAN_FUNCTION_SCHEMA],
        function_call={"name": "report_findings"},
        temperature=0.1,
    )

    usage = _extract_usage(response)
    findings = _parse_scan_response(response, file_path)
    return findings, usage


def _parse_scan_response(response: Any, file_path: str) -> list[LLMFinding]:
    """Parse the function call response into LLMFinding objects."""
    message = response.choices[0].message

    if not message.function_call:
        return []

    try:
        data = json.loads(message.function_call.arguments)
    except json.JSONDecodeError:
        return []

    findings: list[LLMFinding] = []
    for item in data.get("findings", []):
        category = item.get("owasp_category", "A10")
        title = item.get("title", "Unknown")
        findings.append(LLMFinding(
            owasp_category=category,
            severity=item.get("severity", "medium"),
            title=title,
            description=item.get("description", ""),
            line_number=item.get("line_number"),
            suggested_fix=item.get("suggested_fix", ""),
            confidence=item.get("confidence", 0.5),
            rule_id=f"llm-{category}-{_slugify(title)}",
        ))
    return findings


# ── Triage ─────────────────────────────────────────────────────────────────


DEFAULT_TRIAGE_MAX_CONCURRENCY = 5
DEFAULT_TRIAGE_PER_CALL_TIMEOUT = 30.0


def _triage_one_sync(
    client: Any,
    model: str,
    finding: dict[str, Any],
    project_context: str | None = None,
) -> tuple[TriageResult | None, LLMUsage]:
    """Triage a single finding via one OpenAI call. Synchronous; intended to be
    invoked from `asyncio.to_thread` so calls run in parallel.
    """
    from owasp_scanner.core.prompts import _wrap_project_context

    user_content = (
        f"{_wrap_project_context(project_context)}"
        "Triage this security finding:\n\n"
        f"Finding ID: {finding['id']}\n"
        f"Title: {finding['title']}\n"
        f"Description: {finding['description']}\n"
        f"File: {finding['file_path']}:{finding.get('line_number', '?')}\n"
        f"Code context:\n```\n"
        f"{finding.get('code_context', finding.get('code_snippet', ''))}\n```\n"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        functions=[TRIAGE_FUNCTION_SCHEMA],
        function_call={"name": "report_triage"},
        temperature=0.1,
    )

    usage = _extract_usage(response)
    parsed = _parse_triage_response(response)
    # Single-finding prompt — pick the assessment matching this finding,
    # falling back to the first if the model didn't echo the id.
    chosen: TriageResult | None = None
    if parsed:
        chosen = next(
            (r for r in parsed if r.finding_id == finding["id"]),
            parsed[0],
        )
        # Ensure the returned result is keyed to the requested finding id
        # so callers can rely on it for auto-update lookups.
        if chosen.finding_id != finding["id"]:
            chosen.finding_id = finding["id"]
    return chosen, usage


async def triage_findings(
    findings_with_context: list[dict[str, Any]],
    *,
    max_concurrency: int = DEFAULT_TRIAGE_MAX_CONCURRENCY,
    per_call_timeout: float = DEFAULT_TRIAGE_PER_CALL_TIMEOUT,
    project_context: str | None = None,
) -> tuple[list[TriageResult], LLMUsage]:
    """Triage regex findings using the LLM, one call per finding in parallel.

    Args:
        findings_with_context: List of dicts with 'id', 'title', 'description',
            'code_context' (expanded snippet), 'file_path', 'line_number'.
        max_concurrency: Max in-flight LLM calls. Defaults to 5; raise for
            higher-tier API keys.
        per_call_timeout: Seconds before a single triage call is abandoned.
            Failed/timed-out findings get a `needs_investigation` verdict
            with the failure reason in `reasoning`.
        project_context: Reviewer-supplied project context prepended to every
            triage prompt. Same semantics as scan_file_llm's project_context.

    Returns (triage results, aggregated usage). Order of results matches
    input order. The per-call design replaces an earlier batched single-prompt
    implementation that could hang the MCP transport on large batches.
    """
    if not findings_with_context:
        return [], LLMUsage(input_tokens=0, output_tokens=0, model=_get_model())

    client = _get_client()
    model = _get_model()
    sem = asyncio.Semaphore(max(1, max_concurrency))
    total = len(findings_with_context)
    done = 0
    done_lock = asyncio.Lock()

    async def triage_one(
        index: int, finding: dict[str, Any]
    ) -> tuple[int, TriageResult, LLMUsage | None]:
        nonlocal done
        result: TriageResult
        usage: LLMUsage | None = None
        async with sem:
            try:
                triage, usage = await asyncio.wait_for(
                    asyncio.to_thread(
                        _triage_one_sync, client, model, finding, project_context,
                    ),
                    timeout=per_call_timeout,
                )
                if triage is None:
                    result = TriageResult(
                        finding_id=finding["id"],
                        verdict="needs_investigation",
                        confidence=0.0,
                        reasoning="LLM returned no assessment for this finding.",
                    )
                else:
                    result = triage
            except TimeoutError:
                logger.warning(
                    "triage timeout for finding %s after %.1fs",
                    finding.get("id"),
                    per_call_timeout,
                )
                result = TriageResult(
                    finding_id=finding["id"],
                    verdict="needs_investigation",
                    confidence=0.0,
                    reasoning=f"Triage timed out after {per_call_timeout:.0f}s.",
                )
            except Exception as exc:  # pragma: no cover — logged + recorded
                logger.warning("triage failed for finding %s: %s", finding.get("id"), exc)
                result = TriageResult(
                    finding_id=finding["id"],
                    verdict="needs_investigation",
                    confidence=0.0,
                    reasoning=f"Triage call failed: {exc}",
                )

        async with done_lock:
            done += 1
            logger.info("triaged %d/%d", done, total)
        return index, result, usage

    tasks = [triage_one(i, f) for i, f in enumerate(findings_with_context)]
    completed = await asyncio.gather(*tasks)
    completed.sort(key=lambda t: t[0])

    results: list[TriageResult] = [t[1] for t in completed]
    total_in = sum(u.input_tokens for _, _, u in completed if u is not None)
    total_out = sum(u.output_tokens for _, _, u in completed if u is not None)
    aggregated = LLMUsage(input_tokens=total_in, output_tokens=total_out, model=model)
    return results, aggregated


def _parse_triage_response(response: Any) -> list[TriageResult]:
    """Parse triage response into TriageResult objects."""
    message = response.choices[0].message

    if not message.function_call:
        return []

    try:
        data = json.loads(message.function_call.arguments)
    except json.JSONDecodeError:
        return []

    results: list[TriageResult] = []
    for item in data.get("assessments", []):
        results.append(TriageResult(
            finding_id=item.get("finding_id", ""),
            verdict=item.get("verdict", "needs_investigation"),
            confidence=item.get("confidence", 0.5),
            reasoning=item.get("reasoning", ""),
            adjusted_severity=item.get("adjusted_severity"),
        ))
    return results


