"""OWASP Scanner MCP Server.

A security audit workbench that scans Python codebases against the OWASP Top 10 (2025),
tracks findings, and persists everything to a local SQLite database.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from owasp_scanner.core import errors
from owasp_scanner.core.config import get_settings
from owasp_scanner.core.config_scanner import (
    detect_framework,
    scan_django_settings,
    scan_fastapi_config,
    scan_general_config,
    scan_nextjs_config,
)
from owasp_scanner.core.database import get_db
from owasp_scanner.core.pip_audit import run_pip_audit
from owasp_scanner.core.reporter import generate_report
from owasp_scanner.core.sarif import generate_sarif
from owasp_scanner.core.scanner import scan_file_content, scan_path, scan_path_hybrid
from owasp_scanner.rules.patterns import OWASP_CATEGORIES, get_rules

mcp = FastMCP("OWASP Scanner")


# ── Prompts ───────────────────────────────────────────────────────────────


@mcp.prompt()
def security_audit(path: str) -> list[dict]:
    """Run a comprehensive security audit on a project. Returns a structured prompt
    that guides the LLM through scanning, deep analysis, and finding creation.

    Args:
        path: Absolute path to the project root.
    """
    return [{"role": "user", "content": f"""\
Run a comprehensive security audit on: {path}

## Workflow

1. **Scan the project:**
   Call `scan_directory("{path}")` to get regex findings across all files.

2. **Check dependencies:**
   Call `scan_dependencies("{path}")` to check for known CVEs.

3. **Check configuration:**
   Find settings/config files and call `scan_config(path)` on each.

4. **Deep analysis on high-value files:**
   For each file that has findings or is a route handler / API endpoint,
   call `scan_file(path, mode="deep")` and review the security checklist
   against the code. If you find design-level issues (missing auth, missing
   rate limiting, missing logging, trust boundary violations), persist them
   using `create_finding`.

5. **Persist design-level findings:**
   For every issue you identify from deep analysis, call `create_finding` with:
   - `file_path`: the file where the issue is
   - `owasp_category`: A01-A10 (use A06 for design issues, A09 for missing logging)
   - `severity`: critical / high / medium / low
   - `title`: concise description (e.g., "No rate limiting on login endpoint")
   - `description`: explain what's wrong and why it matters
   - `line_number`: if applicable
   - `suggested_fix`: concrete remediation step
   - `confidence`: 0.0-1.0 (your confidence this is a real issue)

6. **Generate report:**
   Call `export_report()` to get the full markdown report.

## Output Format

Present your findings as:

### Summary
- Total findings (regex + your analysis)
- Breakdown by severity
- Top 3 most urgent issues with one-line explanations

### Critical & High Findings
For each critical/high finding:
- **[SEVERITY] Title** — `file:line`
  Description of the vulnerability and its impact.
  **Fix:** concrete remediation step.

### Design Issues (from deep analysis)
Issues you found that regex couldn't — missing controls, insecure patterns,
trust boundary violations. These are often the most important findings.

### Dependency Vulnerabilities
CVEs found by pip-audit, with upgrade paths.

### Configuration Issues
Misconfigurations found in settings files.

### Recommendations
Prioritized next steps: what to fix first and why.
"""}]


# ── Scanning Tools ─────────────────────────────────────────────────────────


_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CATEGORIES = set(OWASP_CATEGORIES.keys())
_VALID_MODES = {"regex", "llm", "hybrid"}


def _validate_mode(mode: str) -> dict[str, Any] | None:
    """Validate scan mode. Returns error dict if invalid, None if OK."""
    if mode not in _VALID_MODES:
        return {"error": f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(_VALID_MODES))}"}
    if mode != "regex":
        from owasp_scanner.core import llm_scanner
        if not llm_scanner.is_available():
            return {
                "error": "LLM scanning requires: pip install owasp-scanner[llm], "
                "OWASP_OPENAI_API_KEY set, and OWASP_LLM_ENABLED=true",
            }
    return None


@mcp.tool()
async def scan_directory(
    path: str,
    owasp_category: str | None = None,
    severity: str | None = None,
    exclude: list[str] | None = None,
    mode: str = "regex",
    git_diff_base: str | None = None,
) -> dict[str, Any]:
    """Scan a directory recursively for OWASP Top 10 security issues.

    Args:
        path: Absolute path to the directory to scan.
        owasp_category: Filter to a specific OWASP category (A01-A10).
        severity: Filter to a minimum severity (critical, high, medium, low).
        exclude: List of path patterns to exclude (e.g. ["tests/", "migrations/", "*.test.py"]).
                 Also reads .owaspignore from the target directory if it exists.
        mode: Scanning mode — 'regex' (free, fast), 'llm' (smart, uses API), or 'hybrid' (regex + LLM triage).
        git_diff_base: If set, only scan files changed between this branch and HEAD (e.g. 'main').
                       Useful for pre-PR security checks — only scans what you're about to ship.
    """
    try:
        mode_err = _validate_mode(mode)
        if mode_err:
            return mode_err

        target = Path(path).resolve()
        if not target.exists():
            return {"error": f"Path does not exist: {path}"}

        # Git-diff mode: only scan changed files
        changed_files: list[Path] | None = None
        if git_diff_base:
            from owasp_scanner.core.scanner import get_changed_files

            repo = target if target.is_dir() else target.parent
            if not (repo / ".git").is_dir():
                return {"error": f"Not a git repository: {repo}"}

            changed_files = get_changed_files(repo, git_diff_base)
            if not changed_files:
                return {
                    "total_findings": 0,
                    "changed_files": 0,
                    "git_diff_base": git_diff_base,
                    "message": f"No files changed between {git_diff_base} and HEAD.",
                }

        # Load .owaspignore if it exists
        all_excludes = list(exclude or [])
        owaspignore = target / ".owaspignore"
        if owaspignore.is_file():
            for line in owaspignore.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    all_excludes.append(line)

        # Detect project type and network surface
        from owasp_scanner.core.nextjs import detect_project_type
        from owasp_scanner.rules.severity import detect_network_surface

        proj_type = detect_project_type(target) if target.is_dir() else "unknown"
        project_surface = detect_network_surface(target) if target.is_dir() else None

        db = get_db()
        scope = "repo" if git_diff_base else ("directory" if target.is_dir() else "file")
        categories_json = json.dumps([owasp_category]) if owasp_category else None
        scan = db.create_scan(scope=scope, target_path=str(target), categories=categories_json)

        if changed_files is not None:
            # Scan only the changed files
            from owasp_scanner.core.scanner import ScanResult

            all_findings = []
            new_count = 0
            existing_count = 0
            for file_path in changed_files:
                file_result = scan_path(file_path, db, scan.id, owasp_category=owasp_category, severity=severity, project_surface=project_surface)
                all_findings.extend(file_result.findings)
                new_count += file_result.new_count
                existing_count += file_result.existing_count
            result = ScanResult(findings=all_findings, new_count=new_count, existing_count=existing_count)
        else:
            result = await scan_path_hybrid(
                target, db, scan.id,
                mode=mode,
                owasp_category=owasp_category,
                severity=severity,
                exclude=all_excludes or None,
                project_type=proj_type,
                project_surface=project_surface,
            )

        db.complete_scan(scan.id, findings_count=len(result.findings))

        # Group by category for summary
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for f in result.findings:
            by_category[f.owasp_category] = by_category.get(f.owasp_category, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        response: dict[str, Any] = {
            "scan_id": scan.id,
            "target": str(target),
            "scope": scope,
            "mode": mode,
            "project_type": proj_type,
            "project_surface": project_surface,
            "total_findings": len(result.findings),
            "new_findings": result.new_count,
            "existing_findings": result.existing_count,
            "by_category": {
                cat: {
                    "label": OWASP_CATEGORIES.get(cat, cat),
                    "count": count,
                }
                for cat, count in sorted(by_category.items())
            },
            "by_severity": by_severity,
            "findings": [f.to_dict() for f in result.findings[:50]],
            "message": (
                f"Found {len(result.findings)} issues ({result.new_count} new, {result.existing_count} existing)."
                if result.findings
                else "No issues found with the current rule set."
            ),
        }

        if git_diff_base:
            response["git_diff_base"] = git_diff_base
            response["changed_files"] = len(changed_files) if changed_files else 0
            response["files_scanned"] = [str(f) for f in changed_files] if changed_files else []

        return response
    except Exception as exc:
        error_id = errors.log_error("scan_directory", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_file(
    path: str,
    owasp_category: str | None = None,
    mode: str = "regex",
) -> dict[str, Any]:
    """Scan a single file for OWASP Top 10 security issues.

    Args:
        path: Absolute path to the file to scan.
        owasp_category: Filter to a specific OWASP category (A01-A10).
        mode: 'regex' (pattern matching), 'deep' (design-level analysis with
              framework detection, endpoint extraction, and security checklist
              for LLM reasoning), or 'llm'/'hybrid' (LLM-powered analysis).
    """
    try:
        target = Path(path).resolve()
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

        if mode == "deep":
            return await _deep_analyze(target)

        if mode in ("llm", "hybrid"):
            mode_err = _validate_mode(mode)
            if mode_err:
                return mode_err

        db = get_db()
        scan = db.create_scan(scope="file", target_path=str(target))

        result = scan_path(target, db, scan.id, owasp_category=owasp_category)
        db.complete_scan(scan.id, findings_count=len(result.findings))

        return {
            "scan_id": scan.id,
            "file": str(target),
            "total_findings": len(result.findings),
            "new_findings": result.new_count,
            "existing_findings": result.existing_count,
            "findings": [f.to_dict() for f in result.findings],
        }
    except Exception as exc:
        error_id = errors.log_error("scan_file", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_dependencies(path: str) -> dict[str, Any]:
    """Scan Python dependencies for known vulnerabilities using pip-audit (A03).

    Supports requirements.txt, pyproject.toml, uv.lock, and poetry.lock.
    Falls back to uv tool run pip-audit if pip-audit is not installed directly.

    Args:
        path: Path to a dependency file (requirements.txt, pyproject.toml, etc.)
              or a directory containing one.
    """
    try:
        target = Path(path).resolve()

        vulns, source = run_pip_audit(target)

        if not vulns:
            return {
                "total_vulnerabilities": 0,
                "source_file": str(source.path),
                "source_type": source.source_type,
                "message": "No known vulnerabilities found in dependencies.",
            }

        # Persist as findings
        db = get_db()
        scan = db.create_scan(
            scope="file", target_path=str(source.path), categories='["A03"]',
        )

        findings = []
        new_count = 0
        for v in vulns:
            fix_str = ", ".join(v.fix_versions) if v.fix_versions else "No fix available"
            finding, is_new = db.create_finding(
                scan_id=scan.id,
                file_path=str(source.path),
                rule_id=f"pip-audit-{v.vuln_id}",
                owasp_category="A03",
                severity="high",
                title=f"{v.package} {v.installed_version}: {v.vuln_id}",
                description=v.description[:500],
                suggested_fix=f"Upgrade {v.package} to {fix_str}",
            )
            findings.append(finding)
            if is_new:
                new_count += 1

        db.complete_scan(scan.id, findings_count=len(findings))

        return {
            "scan_id": scan.id,
            "source_file": str(source.path),
            "source_type": source.source_type,
            "total_vulnerabilities": len(vulns),
            "new_findings": new_count,
            "existing_findings": len(findings) - new_count,
            "vulnerabilities": [v.to_dict() for v in vulns],
            "message": f"Found {len(vulns)} vulnerabilities in {source.path.name}.",
        }
    except FileNotFoundError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        error_id = errors.log_error("scan_dependencies", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_config(
    path: str,
    framework: str = "auto",
) -> dict[str, Any]:
    """Scan a configuration file for security misconfigurations.

    Supports Django, FastAPI, Flask, MCP servers, and general Python config.
    Falls back to general security checks if the framework is unknown.

    Args:
        path: Path to settings.py (Django), main app file (FastAPI/Flask/MCP), or any config file.
        framework: 'django', 'fastapi', 'general', or 'auto' (auto-detect).
    """
    try:
        target = Path(path).resolve()
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

        content = target.read_text(encoding="utf-8", errors="replace")

        # Detect or use specified framework
        fw = framework.lower()
        if fw == "auto":
            fw = detect_framework(content)

        if fw == "django":
            config_checks = scan_django_settings(content)
        elif fw == "fastapi":
            config_checks = scan_fastapi_config(content)
        elif fw == "nextjs":
            config_checks = scan_nextjs_config(content)
        else:
            # Fall back to general checks for unknown, mcp, flask, etc.
            config_checks = scan_general_config(content)

        # Persist as findings
        db = get_db()
        scan = db.create_scan(
            scope="file", target_path=str(target),
            categories='["A02"]',
        )

        findings = []
        new_count = 0
        for check in config_checks:
            finding, is_new = db.create_finding(
                scan_id=scan.id,
                file_path=str(target),
                rule_id=f"config-{check.setting}",
                owasp_category="A02",
                severity=check.severity,
                title=check.title,
                description=f"{check.description} (expected: {check.expected}, actual: {check.actual})",
                suggested_fix=f"Set {check.setting} = {check.expected}",
            )
            findings.append(finding)
            if is_new:
                new_count += 1

        db.complete_scan(scan.id, findings_count=len(findings))

        return {
            "scan_id": scan.id,
            "file": str(target),
            "framework": fw,
            "total_checks": len(config_checks),
            "new_findings": new_count,
            "existing_findings": len(findings) - new_count,
            "checks": [c.to_dict() for c in config_checks],
            "message": (
                f"Found {len(config_checks)} configuration issues in {fw} settings."
                if config_checks
                else f"No configuration issues found in {fw} settings."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("scan_config", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


async def _deep_analyze(target: Path) -> dict[str, Any]:
    """Design-level security analysis of a single file.

    Returns structured context — detected framework, endpoints, decorators,
    imports — plus a security checklist for LLM reasoning.
    Called by scan_file(mode="deep").
    """
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")

        # Extract structural information
        imports = [ln.strip() for ln in lines if ln.strip().startswith(("import ", "from "))]

        decorators = []
        endpoints = []
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("@"):
                decorators.append({"line": i, "decorator": stripped})
            # FastAPI/Flask routes
            if re.match(r"^\s*@app\.(get|post|put|delete|patch)\s*\(", stripped):
                endpoints.append({"line": i, "type": "route", "detail": stripped})
            # MCP tools
            if re.match(r"^\s*@mcp\.tool\s*\(", stripped):
                endpoints.append({"line": i, "type": "mcp_tool", "detail": stripped})
            # Next.js route handlers
            if re.match(r"^\s*export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(", stripped):
                endpoints.append({"line": i, "type": "route_handler", "detail": stripped})
            # Next.js server actions
            if re.match(r"^\s*export\s+(?:async\s+)?function\s+\w+\s*\(", stripped):
                if "'use server'" in content or '"use server"' in content:
                    endpoints.append({"line": i, "type": "server_action", "detail": stripped})
            # Django views
            if re.match(r"^\s*def\s+\w+.*request", stripped):
                endpoints.append({"line": i, "type": "handler", "detail": stripped})

        # Detect framework
        framework = detect_framework(content)

        # Build framework-aware checklist
        base_checklist = [
            {
                "check": "Authorization",
                "question": "Does every endpoint verify the user has permission for the specific resource?",
                "look_for": "permission checks, role verification, object-level access control",
            },
            {
                "check": "Rate Limiting",
                "question": "Are sensitive endpoints (login, password reset, API) rate-limited?",
                "look_for": "rate limit decorators, throttle middleware, slowapi",
            },
            {
                "check": "Input Validation",
                "question": "Is all user input validated server-side with allow-lists?",
                "look_for": "Pydantic models, form validation, type checking on inputs",
            },
            {
                "check": "Error Handling",
                "question": "Are exceptions caught specifically, logged, and not leaked to users?",
                "look_for": "try/except blocks, generic error responses, logging calls",
            },
            {
                "check": "Security Logging",
                "question": "Are authentication, authorization, and validation events logged?",
                "look_for": "logger.info/warning on auth events, structured logging",
            },
            {
                "check": "Database Transactions",
                "question": "Are multi-step database operations wrapped in transactions?",
                "look_for": "db.transaction(), atomic blocks, commit/rollback patterns",
            },
            {
                "check": "Secrets Management",
                "question": "Are credentials loaded from environment/secrets manager, not hardcoded?",
                "look_for": "os.environ, settings.SECRET_KEY loaded dynamically",
            },
        ]

        # Add framework-specific checks
        if framework == "mcp":
            base_checklist.extend([
                {
                    "check": "Tool Input Sanitization",
                    "question": "Do MCP tools validate and sanitize all parameters before use?",
                    "look_for": "type validation, path traversal checks, command injection prevention in tool params",
                },
                {
                    "check": "Code Execution Risk",
                    "question": "Do any tools accept user code, file paths, or shell commands as parameters?",
                    "look_for": "subprocess calls, eval/exec, file operations using tool parameters — these are high risk",
                },
                {
                    "check": "Data Exfiltration Surface",
                    "question": "Could tool responses leak sensitive data (env vars, secrets, file contents)?",
                    "look_for": "tools that read files, environment, or configs and return raw content",
                },
            ])

        if framework == "nextjs":
            base_checklist.extend([
                {
                    "check": "Server/Client Boundary",
                    "question": "Are props passed from Server Components to Client Components minimized to only what the UI needs?",
                    "look_for": "Full ORM objects passed as props, objects named user/session/token crossing the boundary",
                },
                {
                    "check": "Server Action Authorization",
                    "question": "Does every Server Action verify auth at the function level (not just middleware)?",
                    "look_for": "'use server' functions without auth checks, reliance on middleware-only auth",
                },
                {
                    "check": "Route Handler Auth",
                    "question": "Do route handlers (route.ts) check authentication and authorization?",
                    "look_for": "GET/POST/PUT/DELETE exports without session/auth validation",
                },
                {
                    "check": "Middleware Coverage",
                    "question": "Does the middleware matcher cover all routes that need protection, including /api/?",
                    "look_for": "matcher array, gaps in route coverage, auth bypassed for certain paths",
                },
                {
                    "check": "Mass Assignment",
                    "question": "Are Server Actions using Object.fromEntries(formData) directly in ORM updates?",
                    "look_for": "Object.fromEntries spread into prisma.update/create without field allowlist",
                },
            ])

        return {
            "file": str(target),
            "framework": framework,
            "line_count": len(lines),
            "imports": imports,
            "decorators": decorators,
            "endpoints": endpoints,
            "content": content,
            "security_checklist": base_checklist,
            "instructions": (
                "Review the file content against each item in the security_checklist. "
                "For each check, determine if the code adequately addresses it. "
                "Report any gaps as potential security concerns with specific line references."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("scan_file", exc, {"path": str(target)})
        return {"error": str(exc), "error_id": error_id}


# ── Findings Management ────────────────────────────────────────────────────


@mcp.tool()
async def list_findings(
    status: str | None = None,
    severity: str | None = None,
    owasp_category: str | None = None,
    file_path: str | None = None,
    scan_id: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List security findings with optional filters.

    Args:
        status: Filter by status (open, in_progress, fixed, accepted, false_positive).
        severity: Filter by severity (critical, high, medium, low).
        owasp_category: Filter by OWASP category (A01-A10).
        file_path: Filter by file path (substring match).
        scan_id: Filter by scan ID.
        limit: Maximum number of results (default 50).
    """
    try:
        db = get_db()
        findings = db.list_findings(
            status=status,
            severity=severity,
            owasp_category=owasp_category,
            file_path=file_path,
            scan_id=scan_id,
            limit=limit,
        )
        return {
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
    except Exception as exc:
        error_id = errors.log_error("list_findings", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Get full details for a specific finding, including audit trail.

    Args:
        finding_id: The UUID of the finding.
    """
    try:
        db = get_db()
        finding = db.get_finding(finding_id)
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}

        audit = db.get_audit_trail(finding_id)
        result = finding.to_dict()
        result["audit_trail"] = [a.to_dict() for a in audit]
        result["owasp_label"] = OWASP_CATEGORIES.get(finding.owasp_category, "")
        return result
    except Exception as exc:
        error_id = errors.log_error("get_finding", exc, {"finding_id": finding_id})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def update_finding(
    finding_id: str,
    status: str | None = None,
    notes: str | None = None,
    fix_commit_sha: str | None = None,
    suggested_fix: str | None = None,
) -> dict[str, Any]:
    """Update a finding's status, notes, or fix details.

    Args:
        finding_id: The UUID of the finding.
        status: New status (open, in_progress, fixed, accepted, false_positive).
        notes: Add notes about the finding (triage rationale, context, etc).
        fix_commit_sha: Git commit SHA that fixes this finding.
        suggested_fix: Updated fix suggestion.
    """
    try:
        db = get_db()
        finding = db.update_finding(
            finding_id,
            status=status,
            notes=notes,
            fix_commit_sha=fix_commit_sha,
            suggested_fix=suggested_fix,
        )
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}
        return {
            "status": "updated",
            "finding": finding.to_dict(),
        }
    except Exception as exc:
        error_id = errors.log_error("update_finding", exc, {"finding_id": finding_id})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def verify_fix(finding_id: str) -> dict[str, Any]:
    """Re-check whether a finding's vulnerability still exists in the source file.

    Reads the file, re-runs the original rule, and auto-closes the finding if
    the pattern is no longer present at or near the original line.

    Args:
        finding_id: The UUID of the finding to verify.
    """
    try:
        db = get_db()
        finding = db.get_finding(finding_id)
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}

        if not finding.rule_id:
            return {
                "error": "Cannot verify: finding has no rule_id (manual finding). "
                "Update status manually.",
            }

        if finding.status in ("fixed", "false_positive"):
            return {
                "status": "already_resolved",
                "finding_status": finding.status,
                "message": f"Finding is already marked as '{finding.status}'.",
            }

        # Look up the rule
        matching_rules = [r for r in get_rules() if r.id == finding.rule_id]
        if not matching_rules:
            return {"error": f"Rule '{finding.rule_id}' not found in current rule set."}
        rule = matching_rules[0]

        # Read the file
        file_path = Path(finding.file_path)
        if not file_path.is_file():
            return {
                "status": "file_missing",
                "message": f"File no longer exists: {finding.file_path}",
            }

        content = file_path.read_text(encoding="utf-8", errors="replace")
        matches = scan_file_content(content, str(file_path), rules=[rule])

        # Check if any match is at or near the original line (±5 lines)
        line = finding.line_number or 0
        nearby = [
            m for m in matches
            if abs(m.line_number - line) <= 5
        ]

        if not nearby:
            # Pattern is gone — auto-fix
            db.update_finding(finding_id, status="fixed")
            return {
                "status": "verified_fixed",
                "message": (
                    f"Pattern '{rule.title}' no longer found near line {line}. "
                    "Finding auto-closed."
                ),
                "finding_id": finding_id,
            }
        else:
            return {
                "status": "still_present",
                "message": (
                    f"Pattern '{rule.title}' still found at "
                    f"line(s) {', '.join(str(m.line_number) for m in nearby)}."
                ),
                "finding_id": finding_id,
                "matches": [m.to_dict() for m in nearby],
            }
    except Exception as exc:
        error_id = errors.log_error("verify_fix", exc, {"finding_id": finding_id})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def create_finding(
    file_path: str,
    owasp_category: str,
    severity: str,
    title: str,
    description: str,
    scan_id: str | None = None,
    line_number: int | None = None,
    code_snippet: str | None = None,
    suggested_fix: str | None = None,
) -> dict[str, Any]:
    """Manually create a security finding (for issues found during code review, pen testing, etc).

    Args:
        file_path: Path to the affected file.
        owasp_category: OWASP category (A01-A10). Categories: A01=Broken Access Control, A02=Security Misconfiguration, A03=Supply Chain, A04=Cryptographic Failures, A05=Injection, A06=Insecure Design, A07=Authentication Failures, A08=Integrity Failures, A09=Logging Failures, A10=Exception Handling.
        severity: Severity level (critical, high, medium, low).
        title: Short title describing the issue.
        description: Detailed description of the vulnerability.
        scan_id: Associate this finding with a specific scan (from scan_directory/scan_file).
        line_number: Line number where the issue occurs.
        code_snippet: Relevant code snippet.
        suggested_fix: Suggested remediation.
    """
    try:
        # Validate severity
        sev = severity.lower()
        if sev not in _VALID_SEVERITIES:
            return {"error": f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"}

        # Validate category
        cat = owasp_category.upper()
        if cat not in _VALID_CATEGORIES:
            return {"error": f"Invalid category '{owasp_category}'. Must be one of: {', '.join(sorted(_VALID_CATEGORIES))}"}

        db = get_db()
        finding, is_new = db.create_finding(
            file_path=file_path,
            owasp_category=cat,
            severity=sev,
            title=title,
            description=description,
            scan_id=scan_id,
            line_number=line_number,
            code_snippet=code_snippet,
            suggested_fix=suggested_fix,
        )
        return {
            "status": "created" if is_new else "existing",
            "finding": finding.to_dict(),
            "owasp_label": OWASP_CATEGORIES.get(cat, cat),
        }
    except Exception as exc:
        error_id = errors.log_error("create_finding", exc, {"file_path": file_path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def delete_finding(finding_id: str) -> dict[str, Any]:
    """Delete a finding permanently (for mistaken entries).

    Args:
        finding_id: The UUID of the finding to delete.
    """
    try:
        db = get_db()
        finding = db.get_finding(finding_id)
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}
        db.delete_finding(finding_id)
        return {
            "status": "deleted",
            "finding_id": finding_id,
            "title": finding.title,
        }
    except Exception as exc:
        error_id = errors.log_error("delete_finding", exc, {"finding_id": finding_id})
        return {"error": str(exc), "error_id": error_id}


# ── LLM Tools ──────────────────────────────────────────────────────────────


@mcp.tool()
async def llm_triage(
    finding_ids: list[str],
    auto_update: bool = False,
) -> dict[str, Any]:
    """Send findings to the LLM for triage — identifies true/false positives.

    Args:
        finding_ids: List of finding UUIDs to triage.
        auto_update: If True, auto-mark high-confidence false positives and add
                     reasoning to notes. If False, return recommendations only.
    """
    try:
        from owasp_scanner.core import llm_scanner

        if not llm_scanner.is_available():
            return {
                "error": "LLM not available. Set OWASP_OPENAI_API_KEY and OWASP_LLM_ENABLED=true.",
            }

        db = get_db()
        findings_context = []
        for fid in finding_ids:
            finding = db.get_finding(fid)
            if not finding:
                continue

            # Expand code context
            try:
                content = Path(finding.file_path).read_text(encoding="utf-8", errors="replace")
                file_lines = content.split("\n")
                line = finding.line_number or 1
                start = max(0, line - 10)
                end = min(len(file_lines), line + 10)
                context = "\n".join(
                    f"{i+1:4d} | {file_lines[i]}" for i in range(start, end)
                )
            except OSError:
                context = finding.code_snippet or ""

            findings_context.append({
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "code_context": context,
            })

        if not findings_context:
            return {"error": "No valid findings found for the provided IDs."}

        results, usage = llm_scanner.triage_findings(findings_context)

        # Auto-update if requested
        updated = []
        if auto_update:
            for tr in results:
                if tr.verdict == "false_positive" and tr.confidence > 0.8:
                    db.update_finding(
                        tr.finding_id,
                        status="false_positive",
                        notes=f"LLM triage ({tr.confidence:.0%}): {tr.reasoning}",
                    )
                    updated.append(tr.finding_id)

        return {
            "triage_results": [r.to_dict() for r in results],
            "auto_updated": updated,
            "llm_usage": usage.to_dict(),
        }
    except Exception as exc:
        error_id = errors.log_error("llm_triage", exc)
        return {"error": str(exc), "error_id": error_id}


# ── Reporting ──────────────────────────────────────────────────────────────


@mcp.tool()
async def get_summary() -> dict[str, Any]:
    """Get a dashboard summary of all findings: counts by status, category, and severity."""
    try:
        db = get_db()
        return db.get_summary()
    except Exception as exc:
        error_id = errors.log_error("get_summary", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def export_report(
    scan_id: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generate a markdown security report.

    Args:
        scan_id: Report on a specific scan. If None, reports on all open findings.
        output_path: Optionally write the report to a file.
    """
    try:
        db = get_db()
        if scan_id:
            findings = db.list_findings(scan_id=scan_id, limit=500)
        else:
            findings = db.list_findings(limit=500)

        scans = db.list_scans()
        report = generate_report(findings, scans)

        if output_path:
            Path(output_path).write_text(report, encoding="utf-8")

        return {
            "report": report,
            "findings_included": len(findings),
            "output_file": output_path,
        }
    except Exception as exc:
        error_id = errors.log_error("export_report", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def export_sarif(
    scan_id: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Export findings in SARIF 2.1.0 format for GitHub, VS Code, and CI tools.

    Args:
        scan_id: Export findings from a specific scan. If None, exports all findings.
        output_path: Optionally write the SARIF JSON to a file.
    """
    try:
        db = get_db()
        if scan_id:
            findings = db.list_findings(scan_id=scan_id, limit=500)
        else:
            findings = db.list_findings(limit=500)

        sarif = generate_sarif(findings)

        if output_path:
            Path(output_path).write_text(
                json.dumps(sarif, indent=2), encoding="utf-8",
            )

        return {
            "sarif": sarif,
            "findings_included": len(findings),
            "output_file": output_path,
        }
    except Exception as exc:
        error_id = errors.log_error("export_sarif", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def create_baseline(path: str) -> dict[str, Any]:
    """Snapshot current open findings as a baseline.

    Creates a .owasp-baseline.json in the target directory containing
    fingerprints of all current open findings. Future scans can exclude
    these to only report new issues.

    Args:
        path: Directory to write the baseline file to.
    """
    try:
        target = Path(path).resolve()
        if not target.is_dir():
            return {"error": f"Not a directory: {path}"}

        db = get_db()
        findings = db.list_findings(status="open", limit=10000)
        fingerprints = [
            f.fingerprint for f in findings if f.fingerprint
        ]

        baseline_path = target / ".owasp-baseline.json"
        baseline = {
            "version": 1,
            "fingerprints": fingerprints,
            "count": len(fingerprints),
        }
        baseline_path.write_text(
            json.dumps(baseline, indent=2), encoding="utf-8",
        )

        return {
            "baseline_file": str(baseline_path),
            "findings_baselined": len(fingerprints),
            "message": (
                f"Baseline created with {len(fingerprints)} findings. "
                "These will be excluded from future scans that use this baseline."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("create_baseline", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def get_trends(days: int = 30) -> dict[str, Any]:
    """Get trend data: findings opened/closed over time and mean time to resolution.

    Args:
        days: Number of days to look back (default 30).
    """
    try:
        db = get_db()
        findings = db.list_findings(limit=10000)

        from datetime import UTC, datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

        # Findings opened in the window
        opened = [f for f in findings if f.found_at >= cutoff]
        # Findings fixed in the window
        fixed = [
            f for f in findings
            if f.fixed_at and f.fixed_at >= cutoff
        ]

        # MTTR (mean time to resolution) for fixed findings
        resolution_times: list[float] = []
        for f in findings:
            if f.fixed_at and f.found_at:
                try:
                    found = datetime.fromisoformat(f.found_at)
                    fixed_at = datetime.fromisoformat(f.fixed_at)
                    delta = (fixed_at - found).total_seconds() / 3600  # hours
                    resolution_times.append(delta)
                except ValueError:
                    pass

        mttr_hours = (
            sum(resolution_times) / len(resolution_times)
            if resolution_times
            else None
        )

        # Group opened by date
        opened_by_date: dict[str, int] = {}
        for f in opened:
            date = f.found_at[:10]  # YYYY-MM-DD
            opened_by_date[date] = opened_by_date.get(date, 0) + 1

        # Group fixed by date
        fixed_by_date: dict[str, int] = {}
        for f in fixed:
            date = f.fixed_at[:10]
            fixed_by_date[date] = fixed_by_date.get(date, 0) + 1

        return {
            "period_days": days,
            "opened_in_period": len(opened),
            "fixed_in_period": len(fixed),
            "currently_open": sum(1 for f in findings if f.status == "open"),
            "mttr_hours": round(mttr_hours, 1) if mttr_hours else None,
            "opened_by_date": dict(sorted(opened_by_date.items())),
            "fixed_by_date": dict(sorted(fixed_by_date.items())),
        }
    except Exception as exc:
        error_id = errors.log_error("get_trends", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def list_scans(limit: int = 20) -> dict[str, Any]:
    """List recent security scans.

    Args:
        limit: Maximum number of scans to return (default 20).
    """
    try:
        db = get_db()
        scans = db.list_scans(limit=limit)
        return {
            "count": len(scans),
            "scans": [s.to_dict() for s in scans],
        }
    except Exception as exc:
        error_id = errors.log_error("list_scans", exc)
        return {"error": str(exc), "error_id": error_id}


# ── Boundary Analysis ─────────────────────────────────────────────────────


@mcp.tool()
async def scan_boundary(
    path: str,
) -> dict[str, Any]:
    """Analyze Next.js Server→Client Component boundary crossings for data leaks.

    Finds places where Server Components pass props to Client Components,
    flags sensitive data (user records, tokens, session objects) that would
    be serialized into the RSC payload and visible in the browser.

    Args:
        path: Path to a Next.js project root or a specific server component file.
    """
    try:
        from owasp_scanner.core.nextjs import (
            analyze_boundary_crossings,
            detect_project_type,
        )

        target = Path(path).resolve()

        if target.is_file():
            project_root = target.parent
            # Walk up to find project root (look for package.json)
            for parent in [target.parent, *target.parent.parents]:
                if (parent / "package.json").is_file():
                    project_root = parent
                    break
            crossings = analyze_boundary_crossings(project_root, target)
        elif target.is_dir():
            proj_type = detect_project_type(target)
            if proj_type not in ("nextjs", "monorepo"):
                return {
                    "error": f"Not a Next.js project (detected: {proj_type}). "
                    "scan_boundary requires a Next.js App Router project.",
                }
            crossings = analyze_boundary_crossings(target)
        else:
            return {"error": f"Path does not exist: {path}"}

        high_risk = [c for c in crossings if c["risk_level"] == "high"]
        sensitive_props = []
        for c in high_risk:
            for p in c["props"]:
                if p["sensitive"]:
                    sensitive_props.append({
                        "server_file": c["server_file"],
                        "client_component": c["client_component"],
                        "prop": p["name"],
                        "value": p["value"],
                        "line": p["line"],
                    })

        return {
            "total_crossings": len(crossings),
            "high_risk": len(high_risk),
            "medium_risk": len(crossings) - len(high_risk),
            "sensitive_props": sensitive_props,
            "crossings": crossings,
            "message": (
                f"Found {len(high_risk)} high-risk boundary crossing(s) "
                f"with sensitive data in props."
                if high_risk
                else (
                    f"Found {len(crossings)} boundary crossing(s), "
                    "none with obviously sensitive prop names."
                    if crossings
                    else "No Server→Client boundary crossings detected."
                )
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("scan_boundary", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


# ── Diagnostics ────────────────────────────────────────────────────────────


@mcp.tool()
async def get_errors(
    error_id: str | None = None,
    tool_name: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Get recent errors from the scanner error log.

    Args:
        error_id: Get a specific error by UUID.
        tool_name: Filter errors by tool name.
        limit: Maximum number of errors to return.
    """
    result = errors.get_errors(error_id=error_id, tool_name=tool_name, limit=limit)
    return {"count": len(result), "errors": result}


@mcp.tool()
async def health_check() -> dict[str, Any]:
    """Check the scanner's health: database connectivity, data directory, rule count."""
    settings = get_settings()
    try:
        db = get_db()
        summary = db.get_summary()
        rules = get_rules()
        return {
            "status": "healthy",
            "data_dir": str(settings.data_dir),
            "db_path": str(settings.db_path),
            "db_exists": settings.db_path.exists(),
            "total_rules": len(rules),
            "total_findings": summary["total_findings"],
            "total_scans": summary["total_scans"],
        }
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}


# ── Entry Point ────────────────────────────────────────────────────────────


def main() -> None:
    """Run as MCP server (default) or CLI scanner with --scan flag."""
    import sys

    if "--version" in sys.argv:
        from owasp_scanner import __version__

        print(f"owasp-scanner {__version__}")
        return

    # CLI mode: owasp-scanner --scan /path [--fail-on=medium]
    if "--scan" in sys.argv:
        import asyncio

        idx = sys.argv.index("--scan")
        target = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "."

        fail_on = "high"
        for arg in sys.argv:
            if arg.startswith("--fail-on="):
                fail_on = arg.split("=", 1)[1].lower()

        fail_levels = {
            "critical": {"critical"},
            "high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"},
        }
        fail_set = fail_levels.get(fail_on, {"critical", "high"})

        async def _cli_scan() -> int:
            result = await scan_directory(target)
            if "error" in result:
                print(f"Error: {result['error']}", file=sys.stderr)
                return 2

            total = result.get("total_findings", 0)
            sev = result.get("by_severity", {})
            print(f"Scanned: {result.get('target', target)}")
            print(f"Findings: {total} ({result.get('new_findings', 0)} new)")
            for s, c in sorted(sev.items()):
                print(f"  {s}: {c}")

            # Check if any findings meet the fail threshold
            failing = sum(sev.get(s, 0) for s in fail_set)
            if failing > 0:
                print(f"\nFAIL: {failing} findings at {fail_on} or above.")
                return 1
            print("\nPASS: No findings at or above threshold.")
            return 0

        sys.exit(asyncio.run(_cli_scan()))
    else:
        mcp.run()


if __name__ == "__main__":
    main()
