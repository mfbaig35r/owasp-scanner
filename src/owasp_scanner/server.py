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
) -> dict[str, Any]:
    """Scan a directory recursively for OWASP Top 10 security issues.

    Args:
        path: Absolute path to the directory to scan.
        owasp_category: Filter to a specific OWASP category (A01-A10).
        severity: Filter to a minimum severity (critical, high, medium, low).
        exclude: List of path patterns to exclude (e.g. ["tests/", "migrations/", "*.test.py"]).
                 Also reads .owaspignore from the target directory if it exists.
        mode: Scanning mode — 'regex' (free, fast), 'llm' (smart, uses API), or 'hybrid' (regex + LLM triage).
    """
    try:
        mode_err = _validate_mode(mode)
        if mode_err:
            return mode_err

        target = Path(path).resolve()
        if not target.exists():
            return {"error": f"Path does not exist: {path}"}

        # Load .owaspignore if it exists
        all_excludes = list(exclude or [])
        owaspignore = target / ".owaspignore"
        if owaspignore.is_file():
            for line in owaspignore.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    all_excludes.append(line)

        # Detect project type
        from owasp_scanner.core.nextjs import detect_project_type

        proj_type = detect_project_type(target) if target.is_dir() else "unknown"

        db = get_db()
        scope = "directory" if target.is_dir() else "file"
        categories_json = json.dumps([owasp_category]) if owasp_category else None
        scan = db.create_scan(scope=scope, target_path=str(target), categories=categories_json)

        result = await scan_path_hybrid(
            target, db, scan.id,
            mode=mode,
            owasp_category=owasp_category,
            severity=severity,
            exclude=all_excludes or None,
            project_type=proj_type,
        )

        db.complete_scan(scan.id, findings_count=len(result.findings))

        # Group by category for summary
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for f in result.findings:
            by_category[f.owasp_category] = by_category.get(f.owasp_category, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            "scan_id": scan.id,
            "target": str(target),
            "scope": scope,
            "mode": mode,
            "project_type": proj_type,
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
    except Exception as exc:
        error_id = errors.log_error("scan_directory", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_file(
    path: str,
    owasp_category: str | None = None,
) -> dict[str, Any]:
    """Scan a single file for OWASP Top 10 security issues.

    Args:
        path: Absolute path to the file to scan.
        owasp_category: Filter to a specific OWASP category (A01-A10).
    """
    try:
        target = Path(path).resolve()
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

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


@mcp.tool()
async def analyze_code(
    code: str,
    filename: str = "snippet.py",
    owasp_category: str | None = None,
) -> dict[str, Any]:
    """Analyze a code snippet for OWASP Top 10 security issues (without saving to database).

    Args:
        code: The source code to analyze.
        filename: Virtual filename (used to determine which rules apply by extension).
        owasp_category: Filter to a specific OWASP category (A01-A10).
    """
    try:
        rules = get_rules(owasp_category=owasp_category)
        matches = scan_file_content(code, filename, rules=rules)
        return {
            "filename": filename,
            "total_findings": len(matches),
            "findings": [m.to_dict() for m in matches],
            "message": (
                f"Found {len(matches)} potential issues in the snippet."
                if matches
                else "No issues detected with the current rule set."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("analyze_code", exc, {"filename": filename})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_changes(
    path: str,
    base_branch: str = "main",
    deep: bool = False,
) -> dict[str, Any]:
    """Scan only files changed between the current branch and a base branch.

    Useful for pre-PR security checks — only scans what you're about to ship.

    Args:
        path: Path to the git repository root.
        base_branch: Branch to diff against (default: 'main').
        deep: Also run deep_analyze on each changed Python file for design-level issues.
    """
    try:
        from owasp_scanner.core.scanner import get_changed_files

        repo = Path(path).resolve()
        if not (repo / ".git").is_dir():
            return {"error": f"Not a git repository: {path}"}

        changed = get_changed_files(repo, base_branch)
        if not changed:
            return {
                "total_findings": 0,
                "changed_files": 0,
                "message": f"No files changed between {base_branch} and HEAD.",
            }

        db = get_db()
        scan = db.create_scan(scope="repo", target_path=str(repo))

        all_findings = []
        new_count = 0
        existing_count = 0
        for file_path in changed:
            result = scan_path(file_path, db, scan.id)
            all_findings.extend(result.findings)
            new_count += result.new_count
            existing_count += result.existing_count

        db.complete_scan(scan.id, findings_count=len(all_findings))

        response: dict[str, Any] = {
            "scan_id": scan.id,
            "base_branch": base_branch,
            "changed_files": len(changed),
            "files_scanned": [str(f) for f in changed],
            "total_findings": len(all_findings),
            "new_findings": new_count,
            "existing_findings": existing_count,
            "findings": [f.to_dict() for f in all_findings[:50]],
        }

        # Deep analysis on changed Python files
        if deep:
            deep_results = []
            for file_path in changed:
                if file_path.suffix == ".py":
                    analysis = await deep_analyze(str(file_path))
                    if "error" not in analysis:
                        deep_results.append({
                            "file": str(file_path),
                            "framework": analysis.get("framework", "unknown"),
                            "endpoints": analysis.get("endpoints", []),
                            "security_checklist": analysis.get("security_checklist", []),
                        })
            response["deep_analysis"] = deep_results

        return response
    except Exception as exc:
        error_id = errors.log_error("scan_changes", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def scan_pr(
    path: str,
    base_branch: str = "main",
    output_format: str = "summary",
) -> dict[str, Any]:
    """Full pre-PR security scan: regex rules + deep analysis + dependency audit.

    Combines scan_changes(deep=True) with scan_dependencies for a complete
    security check suitable for a PR comment or CI check.

    Args:
        path: Path to the git repository root.
        base_branch: Branch to diff against (default: 'main').
        output_format: 'summary' (default), 'sarif', or 'markdown'.
    """
    try:
        # Run combined scan
        changes_result = await scan_changes(path, base_branch, deep=True)
        if "error" in changes_result:
            return changes_result

        # Try dependency scan (non-fatal if no requirements found)
        dep_result = await scan_dependencies(path)
        dep_vulns = dep_result.get("total_vulnerabilities", 0)

        # Determine severity counts from regex findings
        severity_counts: dict[str, int] = {}
        for f in changes_result.get("findings", []):
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        has_critical = severity_counts.get("critical", 0) > 0
        has_high = severity_counts.get("high", 0) > 0

        result: dict[str, Any] = {
            "scan_id": changes_result.get("scan_id"),
            "base_branch": base_branch,
            "changed_files": changes_result.get("changed_files", 0),
            "regex_findings": changes_result.get("total_findings", 0),
            "new_findings": changes_result.get("new_findings", 0),
            "dependency_vulnerabilities": dep_vulns,
            "severity_counts": severity_counts,
            "pass": not has_critical and not has_high and dep_vulns == 0,
            "findings": changes_result.get("findings", []),
            "deep_analysis": changes_result.get("deep_analysis", []),
        }

        if dep_result.get("vulnerabilities"):
            result["dependency_details"] = dep_result["vulnerabilities"]

        # Format output
        if output_format == "sarif":
            db = get_db()
            scan_id = changes_result.get("scan_id")
            if scan_id:
                findings = db.list_findings(scan_id=scan_id, limit=500)
                result["sarif"] = generate_sarif(findings)

        elif output_format == "markdown":
            db = get_db()
            scan_id = changes_result.get("scan_id")
            if scan_id:
                findings = db.list_findings(scan_id=scan_id, limit=500)
                scans = db.list_scans(limit=1)
                result["report"] = generate_report(findings, scans)

        return result
    except Exception as exc:
        error_id = errors.log_error("scan_pr", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def deep_analyze(path: str) -> dict[str, Any]:
    """Analyze a file for design-level security concerns that regex rules can't catch.

    Returns structured context about the file — detected framework, endpoints,
    decorators, imports — plus a security checklist for the LLM to reason over.
    Use this when you need to find issues like missing rate limiting, missing
    authorization, or insecure design patterns.

    Args:
        path: Path to the file to analyze.
    """
    try:
        target = Path(path).resolve()
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

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

        # Cross-file taint analysis (1-hop for deep_analyze)
        cross_file_flows: list[dict[str, Any]] = []
        try:
            from owasp_scanner.core.dataflow import trace_dataflows
            flows = trace_dataflows(
                target.parent, target_file=target, max_hops=1,
            )
            if flows:
                cross_file_flows = [f.to_dict() for f in flows]
                base_checklist.append({
                    "check": "Cross-File Data Flow",
                    "question": (
                        f"Found {len(flows)} data flow(s) from this file to "
                        "dangerous operations in other files. Are they sanitized?"
                    ),
                    "look_for": "input validation before cross-file calls, "
                    "parameterized queries, path validation",
                    "flows": cross_file_flows,
                })
        except Exception:
            pass  # Non-fatal — cross-file analysis is best-effort

        return {
            "file": str(target),
            "framework": framework,
            "line_count": len(lines),
            "imports": imports,
            "decorators": decorators,
            "endpoints": endpoints,
            "content": content,
            "security_checklist": base_checklist,
            "cross_file_flows": cross_file_flows,
            "instructions": (
                "Review the file content against each item in the security_checklist. "
                "For each check, determine if the code adequately addresses it. "
                "Report any gaps as potential security concerns with specific line references."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("deep_analyze", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def trace_dataflow(
    path: str,
    source: str | None = None,
    max_hops: int = 3,
) -> dict[str, Any]:
    """Trace tainted data from MCP tools/API endpoints through function calls to dangerous sinks.

    Performs cross-file static analysis to find paths where user input reaches
    dangerous operations (subprocess, eval, SQL, file access) without sanitization.

    Args:
        path: Project root directory or specific Python file to analyze.
        source: Optional specific function name to trace from (e.g. 'run_python').
        max_hops: Maximum call depth to trace (default 3).
    """
    try:
        from owasp_scanner.core.dataflow import analyze_file, trace_dataflows

        target = Path(path).resolve()

        if target.is_file():
            project_root = target.parent
            target_file = target
        else:
            project_root = target
            target_file = None

        flows = trace_dataflows(project_root, target_file, max_hops)

        # Filter by source function if specified
        if source:
            flows = [f for f in flows if f.source_function == source]

        # Collect taint sources for the summary
        if target_file:
            functions, _ = analyze_file(target_file)
        else:
            functions = []
            for f in project_root.rglob("*.py"):
                if any(s in f.parts for s in (".venv", "__pycache__", ".git")):
                    continue
                funcs, _ = analyze_file(f)
                functions.extend(funcs)

        taint_sources = [
            {
                "file": func.file,
                "function": func.name,
                "params": func.params,
                "line": func.line,
                "decorators": func.decorators,
            }
            for func in functions if func.is_taint_source
        ]

        unsanitized = [f for f in flows if not f.sanitized]

        return {
            "taint_sources": taint_sources,
            "total_flows": len(flows),
            "unsanitized_flows": len(unsanitized),
            "taint_flows": [f.to_dict() for f in flows],
            "summary": (
                f"Found {len(unsanitized)} unsanitized data flow(s) "
                f"from user input to dangerous operations."
                if unsanitized
                else "No unsanitized taint flows detected."
            ),
        }
    except Exception as exc:
        error_id = errors.log_error("trace_dataflow", exc, {"path": path})
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


# ── Test Quality Tools ──────────────────────────────────────────────────────


@mcp.tool()
async def scan_test_quality(
    path: str,
    language: str = "auto",
    exclude: list[str] | None = None,
    mode: str = "regex",
) -> dict[str, Any]:
    """Scan a project for test quality gaps: missing tests, weak assertions, untested error paths.

    Args:
        path: Absolute path to the project root.
        language: 'python', 'rust', 'hybrid', or 'auto' (detect).
        exclude: Path patterns to exclude.
        mode: 'regex' (free, fast) or 'llm' (smart, uses API).
    """
    try:
        from owasp_scanner.core.test_analyzer import scan_project_test_quality
        from owasp_scanner.rules.test_quality_patterns import TEST_QUALITY_CATEGORIES

        target = Path(path).resolve()
        if not target.is_dir():
            return {"error": f"Not a directory: {path}"}

        db = get_db()
        scan = db.create_scan(
            scope="directory", target_path=str(target),
            categories='["test_quality"]',
        )

        result = await scan_project_test_quality(
            target, db, scan.id,
            language=language, exclude=exclude, mode=mode,
        )

        db.complete_scan(scan.id, findings_count=len(result.findings))

        by_category: dict[str, int] = {}
        for f in result.findings:
            by_category[f.owasp_category] = by_category.get(f.owasp_category, 0) + 1

        return {
            "scan_id": scan.id,
            "target": str(target),
            "mode": mode,
            "total_findings": len(result.findings),
            "new_findings": result.new_count,
            "existing_findings": result.existing_count,
            "by_category": {
                cat: {
                    "label": TEST_QUALITY_CATEGORIES.get(cat, cat),
                    "count": count,
                }
                for cat, count in sorted(by_category.items())
            },
            "findings": [f.to_dict() for f in result.findings[:50]],
        }
    except Exception as exc:
        error_id = errors.log_error("scan_test_quality", exc, {"path": path})
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def analyze_test_coverage(
    source_file: str,
    test_file: str | None = None,
) -> dict[str, Any]:
    """Deep analysis of test coverage for a single source file.

    Args:
        source_file: Path to the source file to analyze.
        test_file: Path to its test file (auto-detected if None).
    """
    try:
        from owasp_scanner.core.llm_scanner import is_available, scan_test_quality_llm
        from owasp_scanner.core.test_pairing import pair_source_to_tests

        source = Path(source_file).resolve()
        if not source.is_file():
            return {"error": f"Not a file: {source_file}"}

        source_content = source.read_text(encoding="utf-8", errors="replace")
        lang = "rust" if source.suffix == ".rs" else "python"

        # Auto-pair if test_file not provided
        test_content = None
        test_path = test_file
        if test_file:
            tp = Path(test_file).resolve()
            if tp.is_file():
                test_content = tp.read_text(encoding="utf-8", errors="replace")
                test_path = str(tp)
        else:
            pairs = pair_source_to_tests(
                source.parent, source_files=[source], language=lang,
            )
            if pairs and pairs[0].candidates:
                best = pairs[0].candidates[0]
                if best.test_path.is_file():
                    test_path = str(best.test_path)
                    test_content = best.test_path.read_text(
                        encoding="utf-8", errors="replace",
                    )

        if not is_available():
            return {
                "error": "LLM required for test coverage analysis. "
                "Set OWASP_OPENAI_API_KEY and OWASP_LLM_ENABLED=true.",
            }

        findings, usage = scan_test_quality_llm(
            source_content, str(source),
            test_content, test_path,
            language=lang,
        )

        return {
            "source_file": str(source),
            "test_file": test_path,
            "language": lang,
            "total_gaps": len(findings),
            "gaps": [f.to_dict() for f in findings],
            "llm_usage": usage.to_dict(),
        }
    except Exception as exc:
        error_id = errors.log_error("analyze_test_coverage", exc)
        return {"error": str(exc), "error_id": error_id}


@mcp.tool()
async def suggest_tests(
    source_file: str,
    max_suggestions: int = 5,
) -> dict[str, Any]:
    """Generate test skeletons for untested code in a source file.

    Args:
        source_file: Path to the source file.
        max_suggestions: Maximum number of test suggestions (default 5).
    """
    try:
        from owasp_scanner.core.llm_scanner import is_available, suggest_tests_llm

        source = Path(source_file).resolve()
        if not source.is_file():
            return {"error": f"Not a file: {source_file}"}

        if not is_available():
            return {
                "error": "LLM required for test suggestions. "
                "Set OWASP_OPENAI_API_KEY and OWASP_LLM_ENABLED=true.",
            }

        content = source.read_text(encoding="utf-8", errors="replace")
        lang = "rust" if source.suffix == ".rs" else "python"

        suggestions, usage = suggest_tests_llm(content, str(source), language=lang)

        return {
            "source_file": str(source),
            "language": lang,
            "total_suggestions": len(suggestions[:max_suggestions]),
            "suggestions": suggestions[:max_suggestions],
            "llm_usage": usage.to_dict(),
        }
    except Exception as exc:
        error_id = errors.log_error("suggest_tests", exc)
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


@mcp.tool()
async def llm_evaluate_dataflows(
    path: str,
    max_hops: int = 3,
) -> dict[str, Any]:
    """Run dataflow analysis then send results to the LLM for exploitability assessment.

    Combines AST-based taint tracing with LLM reasoning to catch issues
    the static analyzer misses (like tainted data in list literals).

    Args:
        path: Project root directory or specific Python file.
        max_hops: Maximum call depth for taint tracing.
    """
    try:
        from owasp_scanner.core import llm_scanner
        from owasp_scanner.core.dataflow import trace_dataflows

        if not llm_scanner.is_available():
            return {
                "error": "LLM not available. Set OWASP_OPENAI_API_KEY and OWASP_LLM_ENABLED=true.",
            }

        target = Path(path).resolve()
        target_file = target if target.is_file() else None
        project_root = target if target.is_dir() else target.parent

        flows = trace_dataflows(project_root, target_file, max_hops)
        flow_dicts = [f.to_dict() for f in flows]

        # Collect source code for context
        source_files: set[str] = set()
        for f in flows:
            source_files.add(f.source_file)
            source_files.add(f.sink_file)

        source_code: dict[str, str] = {}
        for sf in source_files:
            try:
                source_code[sf] = Path(sf).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        assessments, usage = llm_scanner.evaluate_dataflows(flow_dicts, source_code)

        return {
            "static_flows": len(flows),
            "assessments": assessments,
            "llm_usage": usage.to_dict(),
        }
    except Exception as exc:
        error_id = errors.log_error("llm_evaluate_dataflows", exc, {"path": path})
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


@mcp.tool()
async def get_scan(scan_id: str) -> dict[str, Any]:
    """Get details for a specific scan, including its findings.

    Args:
        scan_id: The UUID of the scan.
    """
    try:
        db = get_db()
        scan = db.get_scan(scan_id)
        if not scan:
            return {"error": f"Scan not found: {scan_id}"}

        findings = db.list_findings(scan_id=scan_id, limit=200)
        result = scan.to_dict()
        result["findings"] = [f.to_dict() for f in findings]
        return result
    except Exception as exc:
        error_id = errors.log_error("get_scan", exc, {"scan_id": scan_id})
        return {"error": str(exc), "error_id": error_id}


# ── Rules & Reference ──────────────────────────────────────────────────────


@mcp.tool()
async def list_rules(
    owasp_category: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """List all available scanning rules with their patterns and descriptions.

    Args:
        owasp_category: Filter rules by OWASP category (A01-A10).
        severity: Filter rules by severity.
    """
    rules = get_rules(owasp_category=owasp_category, severity=severity)
    return {
        "count": len(rules),
        "rules": [r.to_dict() for r in rules],
        "owasp_categories": OWASP_CATEGORIES,
    }


@mcp.tool()
async def get_owasp_reference(category: str) -> dict[str, Any]:
    """Get a reference description for an OWASP Top 10 category.

    Args:
        category: OWASP category code (A01-A10).
    """
    references = {
        "A01": {
            "name": "Broken Access Control",
            "rank": 1,
            "description": "Authentication without authorization, IDOR, path traversal, missing object-level access checks, over-permissive APIs.",
            "key_defenses": [
                "Check authorization on every endpoint, not just authentication",
                "Object-level access control: verify the user owns the resource",
                "Validate file paths against allowed directories (prevent traversal)",
                "Default deny: new endpoints require explicit permission grants",
            ],
            "python_traps": [
                "@login_required without @permission_required",
                "FileResponse(f'/uploads/{user_input}') without path validation",
                "Returning all records and filtering on the frontend",
            ],
            "owasp_url": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
        },
        "A02": {
            "name": "Security Misconfiguration",
            "rank": 2,
            "description": "Debug mode in production, default credentials, missing security headers, Docker ports bypassing firewalls, source maps shipped to production.",
            "key_defenses": [
                "DEBUG = False in production",
                "Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options",
                "Docker ports bound to 127.0.0.1 or using internal networks",
                "Cookie flags: Secure, HttpOnly, SameSite=Lax",
                "CSRF protection enabled",
            ],
            "python_traps": [
                "DEBUG = True in Django production settings",
                "ALLOWED_HOSTS = ['*']",
                "Hardcoded SECRET_KEY",
                "Docker port 5432:5432 bypassing UFW",
            ],
            "owasp_url": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/",
        },
        "A03": {
            "name": "Software Supply Chain Failures",
            "rank": 3,
            "description": "Vulnerable dependencies, malicious packages, unpinned dependencies, compromised CI/CD, developer workstation compromise.",
            "key_defenses": [
                "Pin dependencies with lock files including hashes",
                "Run pip-audit in CI",
                "Don't auto-update to latest — use a 3-7 day delay",
                "2FA on all package registries",
                "Secret scanning in CI",
            ],
            "python_traps": [
                "pip install without pinned versions",
                "No pip-audit in CI pipeline",
                "Auto-updating to latest (LiteLLM incident: 30 min exposure, 50K machines)",
            ],
            "owasp_url": "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
        },
        "A04": {
            "name": "Cryptographic Failures",
            "rank": 4,
            "description": "Weak hashing (MD5, SHA-1), missing encryption, hardcoded keys, using random instead of secrets.",
            "key_defenses": [
                "Argon2id for passwords, SHA-256/SHA-3 for hashing, AES-256-GCM for encryption",
                "secrets module for tokens (never random)",
                "TLS enforced end-to-end",
                "Keys from environment variables or secrets manager",
            ],
            "python_traps": [
                "hashlib.md5() for password hashing",
                "random.choices() for token generation",
                "requests.get(url, verify=False)",
                "Hardcoded SECRET_KEY or encryption keys",
            ],
            "owasp_url": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
        },
        "A05": {
            "name": "Injection",
            "rank": 5,
            "description": "SQL injection, NoSQL injection, command injection, unsafe deserialization (pickle, yaml.load), template injection.",
            "key_defenses": [
                "Parameterized queries for all database access",
                "Allow-list input validation",
                "subprocess.run() with list args, shell=False",
                "yaml.safe_load(), never pickle.loads() on untrusted data",
                "Context-aware output encoding for XSS prevention",
            ],
            "python_traps": [
                "f-string SQL queries",
                "os.system() or subprocess(shell=True)",
                "pickle.loads() on user data",
                "yaml.load() without SafeLoader",
                "Template(f'Hello {user_input}')",
            ],
            "owasp_url": "https://owasp.org/Top10/A05_2025-Injection/",
        },
        "A06": {
            "name": "Insecure Design",
            "rank": 6,
            "description": "Missing rate limiting, client-side-only validation, no threat model, missing security requirements.",
            "key_defenses": [
                "Rate limiting on auth and sensitive endpoints",
                "Server-side validation (client-side is UX only)",
                "Threat model before implementation (STRIDE)",
                "Security requirements defined upfront",
            ],
            "python_traps": [
                "Login endpoint with no rate limiting",
                "API trusts frontend validation",
                "Password reset reveals whether email is registered",
            ],
            "owasp_url": "https://owasp.org/Top10/A06_2025-Insecure_Design/",
        },
        "A07": {
            "name": "Authentication Failures",
            "rank": 7,
            "description": "Rolling your own auth, no brute force protection, weak passwords, missing MFA, predictable session tokens.",
            "key_defenses": [
                "Use a proven identity provider (Auth0, Okta, Azure AD, Keycloak)",
                "Brute force and credential stuffing protection",
                "MFA with risk-based step-up",
                "Session rotation after login, invalidation on logout",
            ],
            "python_traps": [
                "Custom auth instead of django.contrib.auth or proven IDP",
                "hashlib.md5(f'{user_id}-{time.time()}') for session tokens",
                "JWT without explicit algorithms list",
                "Hardcoded passwords/API keys",
            ],
            "owasp_url": "https://owasp.org/Top10/A07_2025-Authentication_Failures/",
        },
        "A08": {
            "name": "Software or Data Integrity Failures",
            "rank": 8,
            "description": "CDN scripts without SRI, unverified package downloads, unsigned CI artifacts, data tampering in transit.",
            "key_defenses": [
                "SRI hashes on all CDN scripts",
                "Package installations with hash verification",
                "Signed CI/CD artifacts",
                "Data integrity checks for sensitive transfers",
            ],
            "python_traps": [
                "<script src='cdn.example.com/lib.js'> without integrity attribute",
                "pip install without --require-hashes",
            ],
            "owasp_url": "https://owasp.org/Top10/A08_2025-Software_and_Data_Integrity_Failures/",
        },
        "A09": {
            "name": "Security Logging and Alerting Failures",
            "rank": 9,
            "description": "No security event logging, only logging successes, logging sensitive data, no alerting on suspicious patterns.",
            "key_defenses": [
                "Log all auth events (success AND failure) with timestamp, user, IP",
                "Structured/JSON logging (prevents log injection)",
                "Never log passwords, tokens, or PII",
                "Alert on brute force, unusual access, privilege escalation",
            ],
            "python_traps": [
                "raise HTTPException(401) with no logging",
                "f-string log messages with unescaped user input (log injection)",
                "Logging passwords or tokens",
            ],
            "owasp_url": "https://owasp.org/Top10/A09_2025-Security_Logging_and_Monitoring_Failures/",
        },
        "A10": {
            "name": "Mishandling of Exceptional Conditions",
            "rank": 10,
            "description": "Silent error swallowing (except: pass), stack traces exposed to users, missing database transactions, no recovery paths.",
            "key_defenses": [
                "Catch specific exceptions, not bare except",
                "Log all errors with context",
                "Generic error messages to users, detailed logs server-side",
                "Database transactions for multi-step operations",
            ],
            "python_traps": [
                "except: pass",
                "except Exception: pass",
                "return {'trace': traceback.format_exc()} to users",
                "Multi-step DB operations without transactions",
            ],
            "owasp_url": "https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/",
        },
    }

    cat = category.upper()
    if cat not in references:
        return {"error": f"Unknown category: {category}. Valid: A01-A10"}
    return references[cat]


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
