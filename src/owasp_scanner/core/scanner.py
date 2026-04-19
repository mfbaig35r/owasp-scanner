"""Core scanning engine — matches rules against source files."""

from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from owasp_scanner.core.config import get_settings
from owasp_scanner.core.database import Database, Finding
from owasp_scanner.rules.patterns import Rule, get_rules
from owasp_scanner.rules.severity import adjust_severity

# Pattern for inline suppression comments: # owasp-ignore: A05-001, A05
_SUPPRESSION_RE = re.compile(r"#\s*owasp-ignore:\s*([\w\-,\s]+)")



# Directories to always skip
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "node_modules", ".venv", "venv", ".env", "env",
    ".tox", ".eggs", "*.egg-info", "dist", "build", ".next", ".nuxt",
}

# File extensions to scan by default
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go",
    ".rb", ".php", ".html", ".htm", ".yml", ".yaml", ".toml",
    ".cfg", ".ini", ".env", ".json",
}


@dataclass
class RuleMatch:
    """A single pattern match within a file."""
    rule: Rule
    file_path: str
    line_number: int
    line_content: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "owasp_category": self.rule.owasp_category,
            "severity": self.rule.severity,
            "title": self.rule.title,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
        }


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.endswith(".egg-info")


def _is_text_file(path: Path) -> bool:
    """Quick check: read first 1KB and look for null bytes (binary indicator)."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" not in chunk
    except OSError:
        return False


def _should_scan_file(path: Path, include_all: bool = False) -> bool:
    settings = get_settings()
    if not include_all and path.suffix not in SCANNABLE_EXTENSIONS:
        return False
    if include_all and not _is_text_file(path):
        return False
    try:
        size_kb = path.stat().st_size / 1024
        if size_kb > settings.max_file_size_kb:
            return False
    except OSError:
        return False
    return True


def _is_excluded(path: Path, root: Path, exclude_patterns: list[str]) -> bool:
    """Check if a path matches any exclude pattern."""
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel, pattern):
            return True
        if fnmatch.fnmatch(path.name, pattern):
            return True
        # Directory prefix match: "tests/" matches "tests/test_foo.py"
        if pattern.endswith("/") and rel.startswith(pattern):
            return True
        if pattern.endswith("/") and f"/{pattern}" in f"/{rel}":
            return True
    return False


def _collect_files(
    target: Path,
    include_all: bool = False,
    exclude: list[str] | None = None,
) -> list[Path]:
    """Recursively collect scannable files.

    Args:
        include_all: If True, include all text files (for secrets scanning).
                     If False, only include files with known code extensions.
        exclude: List of path patterns to exclude.
    """
    if target.is_file():
        return [target] if _should_scan_file(target, include_all) else []

    exclude_patterns = exclude or []
    files: list[Path] = []
    for item in sorted(target.rglob("*")):
        # Skip directories in SKIP_DIRS — but only check parent dirs, not the filename
        if any(_should_skip_dir(part) for part in item.parent.parts):
            continue
        if exclude_patterns and _is_excluded(item, target, exclude_patterns):
            continue
        if item.is_file() and _should_scan_file(item, include_all):
            files.append(item)
    return files


def _match_rule_glob(rule: Rule, file_path: Path) -> bool:
    """Check if a rule applies to this file type."""
    return fnmatch.fnmatch(file_path.name, rule.file_glob)


def _is_suppressed(lines: list[str], line_number: int, rule: Rule) -> bool:
    """Check if a match is suppressed by an inline # owasp-ignore comment.

    Checks the matching line itself and the line above it.
    Supports rule IDs (A05-001) and category codes (A05).
    """
    for offset in (0, -1):  # current line, then line above
        idx = line_number - 1 + offset  # 0-indexed
        if 0 <= idx < len(lines):
            m = _SUPPRESSION_RE.search(lines[idx])
            if m:
                suppressed = {s.strip() for s in m.group(1).split(",")}
                if rule.id in suppressed or rule.owasp_category in suppressed:
                    return True
    return False


def scan_file_content(
    content: str,
    file_path: str,
    rules: list[Rule] | None = None,
) -> list[RuleMatch]:
    """Scan file content against rules. Returns matches."""
    if rules is None:
        rules = get_rules()

    matches: list[RuleMatch] = []
    lines = content.split("\n")
    path = Path(file_path)

    for rule in rules:
        if not _match_rule_glob(rule, path):
            continue

        # Search line by line for context
        for i, line in enumerate(lines, start=1):
            if rule.pattern.search(line):
                if not _is_suppressed(lines, i, rule):
                    matches.append(RuleMatch(
                        rule=rule,
                        file_path=file_path,
                        line_number=i,
                        line_content=line,
                    ))

        # Also search across multi-line blocks (for patterns spanning lines)
        # e.g., @login_required\n followed by no authz decorator
        for m in rule.pattern.finditer(content):
            line_num = content[:m.start()].count("\n") + 1
            # Avoid duplicates from line-by-line scan
            if not any(
                rm.rule.id == rule.id and rm.line_number == line_num
                for rm in matches
            ):
                if not _is_suppressed(lines, line_num, rule):
                    matched_text = m.group(0).split("\n")[0]
                    matches.append(RuleMatch(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=matched_text,
                    ))

    return matches


def get_changed_files(repo_path: Path, base_branch: str = "main") -> list[Path]:
    """Get files changed between the current branch and a base branch.

    Args:
        repo_path: Root of the git repository.
        base_branch: Branch to diff against (default: main).

    Returns:
        List of absolute paths to changed files.

    Raises:
        RuntimeError: If git command fails.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_branch}...HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not in PATH")

    if result.returncode != 0:
        raise RuntimeError(f"git diff failed: {result.stderr.strip()}")

    files: list[Path] = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            full_path = repo_path / line
            if full_path.is_file():
                files.append(full_path)
    return files


@dataclass
class ScanResult:
    """Result of a scan_path operation with dedup tracking."""
    findings: list[Finding]
    new_count: int
    existing_count: int


def scan_path(
    target: Path,
    db: Database,
    scan_id: str,
    *,
    owasp_category: str | None = None,
    severity: str | None = None,
    exclude: list[str] | None = None,
) -> ScanResult:
    """Scan a file or directory and persist findings to the database."""
    rules = get_rules(owasp_category=owasp_category, severity=severity)
    include_all = any(r.file_glob == "*" for r in rules)
    files = _collect_files(target, include_all=include_all, exclude=exclude)
    all_findings: list[Finding] = []
    new_count = 0
    existing_count = 0

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue

        matches = scan_file_content(content, str(file_path), rules=rules)

        for match in matches:
            # Extract code snippet (3 lines of context)
            lines = content.split("\n")
            start = max(0, match.line_number - 2)
            end = min(len(lines), match.line_number + 2)
            snippet = "\n".join(
                f"{i+1:4d} | {lines[i]}"
                for i in range(start, end)
            )

            # Adjust severity based on file context
            effective_severity = adjust_severity(
                match.rule.severity, match.file_path,
            )

            finding, is_new = db.create_finding(
                scan_id=scan_id,
                file_path=match.file_path,
                line_number=match.line_number,
                rule_id=match.rule.id,
                owasp_category=match.rule.owasp_category,
                severity=effective_severity,
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

    return ScanResult(
        findings=all_findings,
        new_count=new_count,
        existing_count=existing_count,
    )


async def scan_path_hybrid(
    target: Path,
    db: Database,
    scan_id: str,
    *,
    mode: str = "regex",
    owasp_category: str | None = None,
    severity: str | None = None,
    exclude: list[str] | None = None,
    project_type: str | None = None,
) -> ScanResult:
    """Scan with regex, LLM, or hybrid mode.

    Modes:
    - regex: existing pattern matching (free, instant)
    - llm: LLM-only scanning (cheap, context-aware)
    - hybrid: regex first, then LLM triage + LLM gap-fill
    """
    if mode == "regex":
        return scan_path(
            target, db, scan_id,
            owasp_category=owasp_category, severity=severity, exclude=exclude,
        )

    from owasp_scanner.core.llm_scanner import scan_file_llm, triage_findings

    rules = get_rules(owasp_category=owasp_category, severity=severity)
    include_all = any(r.file_glob == "*" for r in rules)
    files = _collect_files(target, include_all=include_all, exclude=exclude)

    all_findings: list[Finding] = []
    new_count = 0
    existing_count = 0

    if mode == "hybrid":
        # Step 1: Regex scan (free, instant)
        regex_result = scan_path(
            target, db, scan_id,
            owasp_category=owasp_category, severity=severity, exclude=exclude,
        )
        all_findings.extend(regex_result.findings)
        new_count += regex_result.new_count
        existing_count += regex_result.existing_count

        # Step 2: LLM triage of regex findings
        if regex_result.findings:
            triage_context = []
            for f in regex_result.findings:
                # Expand code context for triage
                try:
                    full_content = Path(f.file_path).read_text(
                        encoding="utf-8", errors="replace",
                    )
                    file_lines = full_content.split("\n")
                    line = f.line_number or 1
                    start = max(0, line - 10)
                    end = min(len(file_lines), line + 10)
                    context = "\n".join(
                        f"{i+1:4d} | {file_lines[i]}" for i in range(start, end)
                    )
                except OSError:
                    context = f.code_snippet or ""

                triage_context.append({
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_context": context,
                })

            triage_results, _ = triage_findings(triage_context)
            for tr in triage_results:
                if tr.verdict == "false_positive" and tr.confidence > 0.8:
                    db.update_finding(
                        tr.finding_id,
                        status="false_positive",
                        notes=f"LLM triage ({tr.confidence:.0%}): {tr.reasoning}",
                    )

    # Step 3 (hybrid) or Step 1 (llm): LLM scan for design-level issues
    scannable_for_llm = {".py"}
    if project_type in ("nextjs", "react"):
        scannable_for_llm.update({".ts", ".tsx", ".js", ".jsx"})

    for file_path in files:
        if file_path.suffix not in scannable_for_llm:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Classify file type for Next.js context
        file_type = None
        if project_type in ("nextjs", "react"):
            from owasp_scanner.core.nextjs import classify_nextjs_file

            project_root = target if target.is_dir() else target.parent
            file_type = classify_nextjs_file(file_path, project_root)

        llm_findings, _ = scan_file_llm(
            content, str(file_path),
            project_type=project_type or "python",
            file_type=file_type,
        )

        for lf in llm_findings:
            finding, is_new = db.create_finding(
                scan_id=scan_id,
                file_path=str(file_path),
                line_number=lf.line_number,
                rule_id=lf.rule_id,
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
