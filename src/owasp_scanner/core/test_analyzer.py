"""Test quality analysis orchestrator — combines pairing, regex, and LLM."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.database import Database, Finding
from owasp_scanner.core.scanner import ScanResult, scan_file_content
from owasp_scanner.core.test_pairing import pair_source_to_tests
from owasp_scanner.rules.patterns import get_rules


async def scan_project_test_quality(
    project_root: Path,
    db: Database,
    scan_id: str,
    *,
    language: str = "auto",
    exclude: list[str] | None = None,
    mode: str = "regex",
) -> ScanResult:
    """Scan a project for test quality gaps.

    Args:
        project_root: Root directory of the project.
        db: Database instance for persistence.
        scan_id: Scan ID for grouping findings.
        language: 'python', 'rust', 'hybrid', or 'auto'.
        exclude: Path patterns to exclude.
        mode: 'regex' or 'llm'/'hybrid' for LLM-powered analysis.
    """
    all_findings: list[Finding] = []
    new_count = 0
    existing_count = 0

    # Step 1: Pair source files to test files
    pairs = pair_source_to_tests(project_root, language=language)

    # Step 2: Run regex rules on test files
    tq_rules = get_rules(category_type="test_quality")
    for pair in pairs:
        # Scan test files with TQ regex rules
        for candidate in pair.candidates:
            if not candidate.test_path.is_file():
                continue
            if candidate.test_path == pair.source and pair.inline_tests:
                continue  # Don't re-scan inline Rust tests as separate files
            try:
                content = candidate.test_path.read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                continue

            matches = scan_file_content(
                content, str(candidate.test_path), rules=tq_rules,
            )
            for match in matches:
                lines = content.split("\n")
                start = max(0, match.line_number - 2)
                end = min(len(lines), match.line_number + 2)
                snippet = "\n".join(
                    f"{i+1:4d} | {lines[i]}" for i in range(start, end)
                )
                finding, is_new = db.create_finding(
                    scan_id=scan_id,
                    file_path=str(candidate.test_path),
                    line_number=match.line_number,
                    rule_id=match.rule.id,
                    category_type="test_quality",
                    owasp_category=match.rule.owasp_category,
                    severity=match.rule.severity,
                    title=match.rule.title,
                    description=match.rule.description,
                    code_snippet=snippet,
                    suggested_fix=match.rule.suggested_fix,
                )
                all_findings.append(finding)
                if is_new:
                    new_count += 1
                else:
                    existing_count += 1

        # Also scan source files with Rust/PyO3 rules
        if pair.language == "rust" and pair.source.suffix == ".rs":
            try:
                content = pair.source.read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                continue
            rs_rules = [
                r for r in tq_rules
                if r.id.startswith(("TQ-RS-", "TQ-PYO3-"))
            ]
            matches = scan_file_content(
                content, str(pair.source), rules=rs_rules,
            )
            for match in matches:
                lines = content.split("\n")
                start = max(0, match.line_number - 2)
                end = min(len(lines), match.line_number + 2)
                snippet = "\n".join(
                    f"{i+1:4d} | {lines[i]}" for i in range(start, end)
                )
                finding, is_new = db.create_finding(
                    scan_id=scan_id,
                    file_path=str(pair.source),
                    line_number=match.line_number,
                    rule_id=match.rule.id,
                    category_type="test_quality",
                    owasp_category=match.rule.owasp_category,
                    severity=match.rule.severity,
                    title=match.rule.title,
                    description=match.rule.description,
                    code_snippet=snippet,
                    suggested_fix=match.rule.suggested_fix,
                )
                all_findings.append(finding)
                if is_new:
                    new_count += 1
                else:
                    existing_count += 1

        # Flag unpaired source files
        if pair.status == "unpaired":
            finding, is_new = db.create_finding(
                scan_id=scan_id,
                file_path=str(pair.source),
                category_type="test_quality",
                owasp_category="TQ09",
                severity="high",
                title=f"No tests found for {pair.source.name}",
                description=f"Source file {pair.source} has no matching test file.",
                suggested_fix="Create a test file with tests for this module.",
            )
            all_findings.append(finding)
            if is_new:
                new_count += 1
            else:
                existing_count += 1

    # Step 3: LLM analysis (if mode is llm or hybrid)
    if mode in ("llm", "hybrid"):
        from owasp_scanner.core.llm_scanner import (
            is_available,
            scan_test_quality_llm,
        )

        if is_available():
            for pair in pairs:
                try:
                    source_content = pair.source.read_text(
                        encoding="utf-8", errors="replace",
                    )
                except OSError:
                    continue

                test_content = None
                test_path = None
                if pair.candidates:
                    best = pair.candidates[0]
                    if best.test_path.is_file() and best.test_path != pair.source:
                        test_path = str(best.test_path)
                        try:
                            test_content = best.test_path.read_text(
                                encoding="utf-8", errors="replace",
                            )
                        except OSError:
                            pass

                llm_findings, _ = scan_test_quality_llm(
                    source_content, str(pair.source),
                    test_content, test_path,
                    language=pair.language,
                )

                for lf in llm_findings:
                    finding, is_new = db.create_finding(
                        scan_id=scan_id,
                        file_path=str(pair.source),
                        rule_id=lf.rule_id,
                        category_type="test_quality",
                        owasp_category=lf.owasp_category,
                        severity=lf.severity,
                        title=lf.title,
                        description=lf.description,
                        suggested_fix=lf.suggested_fix,
                        confidence=lf.confidence,
                    )
                    all_findings.append(finding)
                    if is_new:
                        new_count += 1
                    else:
                        existing_count += 1

    return ScanResult(
        findings=all_findings,
        new_count=new_count,
        existing_count=existing_count,
    )
