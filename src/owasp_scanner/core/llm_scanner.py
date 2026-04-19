"""LLM-powered security scanning using OpenAI-compatible APIs.

Wraps the OpenAI SDK to scan code for OWASP Top 10 vulnerabilities,
triage regex findings, and evaluate dataflow exploitability.
Supports any OpenAI-compatible API via base_url override.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from owasp_scanner.core.config import get_settings
from owasp_scanner.core.prompts import (
    DATAFLOW_FUNCTION_SCHEMA,
    DATAFLOW_SYSTEM_PROMPT,
    NEXTJS_SCAN_SYSTEM_PROMPT,
    SCAN_FUNCTION_SCHEMA,
    SCAN_SYSTEM_PROMPT,
    TRIAGE_FUNCTION_SCHEMA,
    TRIAGE_SYSTEM_PROMPT,
    build_nextjs_file_context,
)

try:
    import openai

    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False


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
) -> tuple[list[LLMFinding], LLMUsage]:
    """Scan a file for security issues using the LLM.

    Args:
        content: File content to scan.
        file_path: Path to the file (for context).
        project_type: 'python', 'nextjs', or 'react' — selects system prompt.
        file_type: Next.js file type for context block (server_component, etc).

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
        user_content = build_nextjs_file_context(file_path, file_type, content)
    else:
        user_content = f"File: {file_path}\n\n```\n{content}\n```"

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


def triage_findings(
    findings_with_context: list[dict[str, Any]],
) -> tuple[list[TriageResult], LLMUsage]:
    """Triage regex findings using the LLM.

    Args:
        findings_with_context: List of dicts with 'id', 'title', 'description',
            'code_context' (expanded snippet), 'file_path', 'line_number'.

    Returns (triage results, usage).
    """
    client = _get_client()
    model = _get_model()

    user_content = "Triage these security findings:\n\n"
    for f in findings_with_context:
        user_content += (
            f"Finding ID: {f['id']}\n"
            f"Title: {f['title']}\n"
            f"Description: {f['description']}\n"
            f"File: {f['file_path']}:{f.get('line_number', '?')}\n"
            f"Code context:\n```\n{f.get('code_context', f.get('code_snippet', ''))}\n```\n\n"
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
    results = _parse_triage_response(response)
    return results, usage


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


# ── Dataflow evaluation ───────────────────────────────────────────────────


def evaluate_dataflows(
    flows: list[dict[str, Any]],
    source_code: dict[str, str],
) -> tuple[list[dict[str, Any]], LLMUsage]:
    """Evaluate taint flows for exploitability using the LLM.

    Args:
        flows: List of taint flow dicts from trace_dataflows.
        source_code: Dict of file_path → file content for context.

    Returns (assessments, usage).
    """
    client = _get_client()
    model = _get_model()

    user_content = "Evaluate these data flows for exploitability:\n\n"
    for i, flow in enumerate(flows):
        user_content += f"Flow {i}:\n{json.dumps(flow, indent=2)}\n\n"

    user_content += "\nRelevant source code:\n\n"
    for path, code in source_code.items():
        # Truncate each file to keep within limits
        truncated = code[:20_000] if len(code) > 20_000 else code
        user_content += f"=== {path} ===\n```\n{truncated}\n```\n\n"

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": DATAFLOW_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        functions=[DATAFLOW_FUNCTION_SCHEMA],
        function_call={"name": "report_dataflow_assessment"},
        temperature=0.1,
    )

    usage = _extract_usage(response)
    message = response.choices[0].message

    if not message.function_call:
        return [], usage

    try:
        data = json.loads(message.function_call.arguments)
    except json.JSONDecodeError:
        return [], usage

    return data.get("assessments", []), usage
