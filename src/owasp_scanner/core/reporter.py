"""Markdown report generation for security scan results."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from owasp_scanner.core.database import Finding, Scan
from owasp_scanner.rules.patterns import OWASP_CATEGORIES

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _fmt_ts(iso_str: str | None) -> str:
    """Format an ISO 8601 timestamp as human-readable UTC."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso_str


def generate_report(
    findings: list[Finding],
    scans: list[Scan] | None = None,
    summary: dict[str, Any] | None = None,
) -> str:
    """Generate a markdown security report."""
    lines: list[str] = []
    lines.append("# Security Scan Report\n")

    # ── Report Metadata ────────────────────────────────────────────────
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"**Generated:** {now}  ")
    if scans:
        scan_dates = sorted(s.started_at[:10] for s in scans if s.started_at)
        lines.append(
            f"**Scan history:** {len(scans)} scans, "
            f"first: {scan_dates[0] if scan_dates else 'N/A'}, "
            f"latest: {scan_dates[-1] if scan_dates else 'N/A'}  "
        )
    lines.append("")

    # ── Executive Summary ──────────────────────────────────────────────
    lines.append("## Executive Summary\n")

    total = len(findings)
    open_findings = [f for f in findings if f.status == "open"]
    by_sev = Counter(f.severity for f in open_findings)

    if total == 0:
        lines.append("No security findings recorded.\n")
        return "\n".join(lines)

    lines.append(f"- **Total findings:** {total}")
    lines.append(f"- **Open:** {len(open_findings)}")
    lines.append(
        f"- **Fixed:** {sum(1 for f in findings if f.status == 'fixed')}"
    )
    lines.append(
        f"- **Accepted/False Positive:** "
        f"{sum(1 for f in findings if f.status in ('accepted', 'false_positive'))}"
    )
    lines.append("")

    if by_sev:
        lines.append("### Open by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            if by_sev.get(sev, 0) > 0:
                lines.append(f"| {sev.upper()} | {by_sev[sev]} |")
        lines.append("")

    # ── By OWASP Category ──────────────────────────────────────────────
    by_cat = Counter(f.owasp_category for f in open_findings)
    if by_cat:
        lines.append("### Open by OWASP Category\n")
        lines.append("| Category | Name | Count |")
        lines.append("|----------|------|-------|")
        for cat in sorted(by_cat.keys()):
            name = OWASP_CATEGORIES.get(cat, cat)
            lines.append(f"| {cat} | {name} | {by_cat[cat]} |")
        lines.append("")

    # ── Top Files ──────────────────────────────────────────────────────
    by_file = Counter(f.file_path for f in open_findings)
    if by_file:
        top_files = by_file.most_common(10)
        lines.append("### Top Files (most open findings)\n")
        lines.append("| File | Findings |")
        lines.append("|------|----------|")
        for path, count in top_files:
            lines.append(f"| `{path}` | {count} |")
        lines.append("")

    # ── Detailed Findings (top 20 by severity) ─────────────────────────
    sorted_findings = sorted(
        open_findings,
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
    )

    lines.append("## Findings Detail\n")
    for i, f in enumerate(sorted_findings[:20], start=1):
        cat_name = OWASP_CATEGORIES.get(f.owasp_category, f.owasp_category)
        lines.append(
            f"### {i}. [{f.severity.upper()}] {f.title}\n"
        )
        lines.append(f"- **Category:** {f.owasp_category} — {cat_name}")
        lines.append(f"- **File:** `{f.file_path}`")
        if f.line_number:
            lines.append(f"- **Line:** {f.line_number}")
        lines.append(f"- **Found:** {_fmt_ts(f.found_at)}")
        if f.updated_at and f.updated_at != f.found_at:
            lines.append(f"- **Last updated:** {_fmt_ts(f.updated_at)}")
        lines.append(f"- **Description:** {f.description}")
        if f.suggested_fix:
            lines.append(f"- **Suggested Fix:** {f.suggested_fix}")
        if f.code_snippet:
            lines.append(f"\n```\n{f.code_snippet}\n```\n")
        lines.append("")

    if len(sorted_findings) > 20:
        lines.append(
            f"*...and {len(sorted_findings) - 20} more open findings.*\n"
        )

    # ── Triaged Findings (accepted/false positive with rationale) ──────
    triaged = [
        f for f in findings
        if f.status in ("accepted", "false_positive") and f.notes
    ]
    if triaged:
        lines.append("## Triaged Findings\n")
        lines.append(
            "*These findings were reviewed and determined to be "
            "acceptable or not applicable.*\n"
        )
        for f in triaged:
            status_label = (
                "False Positive" if f.status == "false_positive"
                else "Accepted Risk"
            )
            lines.append(
                f"- **[{status_label}]** {f.title} (`{f.file_path}`)"
            )
            lines.append(f"  - *Rationale:* {f.notes}")
            lines.append(f"  - *Triaged:* {_fmt_ts(f.updated_at)}")
        lines.append("")

    # ── Remediation Priority ───────────────────────────────────────────
    lines.append("## Remediation Priority\n")
    lines.append(
        "1. **Critical findings** — fix immediately, "
        "these are actively exploitable"
    )
    lines.append(
        "2. **High findings** — fix before next release"
    )
    lines.append(
        "3. **Medium findings** — schedule for upcoming sprint"
    )
    lines.append(
        "4. **Low findings** — address when touching the affected code"
    )
    lines.append("")

    return "\n".join(lines)
