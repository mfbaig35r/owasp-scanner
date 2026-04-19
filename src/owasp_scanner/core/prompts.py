"""System prompts and function schemas for LLM-powered scanning."""

from __future__ import annotations

# ── Scanning ───────────────────────────────────────────────────────────────

SCAN_SYSTEM_PROMPT = """\
You are a security auditor specializing in the OWASP Top 10 (2025).
Analyze the provided source code for security vulnerabilities.

Focus especially on issues that pattern matching cannot detect:
- A01 Broken Access Control: missing authorization checks, IDOR, SSRF, object-level access gaps
- A02 Security Misconfiguration: unsafe defaults, missing headers, exposed debug info, XXE
- A03 Supply Chain: unpinned deps, installs from git/HTTP, missing hash verification, \
no SBOM, use of unmaintained packages, typosquatting risk in imports
- A04 Cryptographic Failures: weak hashing, missing encryption, hardcoded keys, ECB mode
- A05 Injection: SQL/NoSQL/command/template injection, unsafe deserialization
- A06 Insecure Design: missing rate limiting, client-only validation, no input allow-lists, \
unrestricted file upload, trust boundary violations, race conditions in multi-step operations, \
missing tenant isolation. This category is about WHAT IS MISSING — the absence of controls \
that should exist. Regex cannot find missing code. You must evaluate whether the design is secure.
- A07 Authentication Failures: custom auth, weak sessions, no brute-force protection
- A08 Integrity Failures: insecure deserialization, missing SRI, unsigned artifacts, mass assignment
- A09 Logging Failures: authentication/authorization events not logged, missing audit trail, \
sensitive data (passwords, tokens, PII) written to logs, no alerting on suspicious patterns, \
f-string log injection. For every auth endpoint, check: is the failure case logged?
- A10 Exception Handling: silent error swallowing, fail-open (returning success on exception), \
leaked stack traces, missing timeouts, missing transactions

Rules:
- Only report real vulnerabilities with specific line references
- Do NOT flag test fixtures, example code, or documentation
- Adjust severity based on context (test file = lower risk, API handler = higher)
- Assign confidence 0.0-1.0 (1.0 = certain, 0.7 = likely, 0.4 = possible)
- If no issues found, return empty findings array
"""

NEXTJS_SCAN_SYSTEM_PROMPT = """\
You are a security auditor specializing in Next.js App Router applications \
and the OWASP Top 10 (2025).

SERVER/CLIENT BOUNDARY:
- Files in app/ are Server Components by default (run on server only).
- 'use client' marks Client Components (run in browser, untrusted).
- Props passed from Server → Client are serialized into the RSC payload \
and visible in the browser (self.__next_f). Full objects are exposed, \
not just rendered fields. This is a data leak vector.
- Server Components can access secrets, databases, internal APIs. \
Client Components cannot.

SERVER ACTIONS:
- 'use server' functions are public HTTP endpoints, callable without forms.
- CSRF protection is Origin-header based and has had bypasses (CVE-2026-27978).
- Every Server Action must validate auth AND input at the function level.
- Object.fromEntries(formData) spread into ORM updates = mass assignment.

MIDDLEWARE:
- Middleware has been bypassed twice (CVE-2024-51479, CVE-2025-29927).
- Auth enforced ONLY in middleware is a critical finding.
- Middleware matchers that miss route segments create auth gaps.
- Auth should be re-checked in pages, actions, and route handlers.

HIGH-PRIORITY PATTERNS:
1. Server Component over-fetching (full DB record → Client Component prop)
2. Server Action mass assignment (formData → ORM without field allowlist)
3. Route handlers without auth checks
4. Middleware matcher gaps (missing /api/ routes)
5. NEXT_PUBLIC_ environment variables exposing secrets
6. Prisma $queryRawUnsafe / raw SQL injection
7. Open redirect via redirect() with user input
8. Cache poisoning via user-controlled revalidatePath/revalidateTag
9. Image SSRF via permissive remotePatterns in next.config.js
10. Cookie manipulation without httpOnly/secure/sameSite flags

Rules:
- Only report real vulnerabilities with specific line references.
- Adjust severity based on context (test file = lower, route handler = higher).
- Assign confidence 0.0-1.0 (1.0 = certain, 0.7 = likely, 0.4 = possible).
- If no issues found, return empty findings array.
"""


def build_nextjs_file_context(
    file_path: str,
    file_type: str,
    content: str,
) -> str:
    """Build LLM user message with file-type context for Next.js files."""
    from owasp_scanner.core.nextjs import FILE_TYPE_CONTEXT

    ctx = FILE_TYPE_CONTEXT.get(file_type, {})
    label = ctx.get("label", file_type.upper())
    trust = ctx.get("trust", "")
    risk = ctx.get("risk", "")

    return (
        f"File: {file_path}\n"
        f"Type: {label}\n"
        f"Trust: {trust}\n"
        f"Risk: {risk}\n\n"
        f"```\n{content}\n```"
    )


# ── Python file context ───────────────────────────────────────────────────

PYTHON_FILE_CONTEXT: dict[str, dict[str, str]] = {
    "fastapi_route": {
        "label": "FASTAPI ROUTE HANDLER",
        "trust": "Public HTTP endpoint. Receives untrusted user input.",
        "risk": (
            "Must validate auth and input at the handler level. "
            "Check for missing rate limiting, IDOR, and injection."
        ),
    },
    "django_view": {
        "label": "DJANGO VIEW",
        "trust": "Public HTTP endpoint via URL routing.",
        "risk": (
            "@login_required checks authentication but not authorization. "
            "Verify object-level access control. Check for raw SQL and "
            "missing CSRF protection on state-changing views."
        ),
    },
    "flask_route": {
        "label": "FLASK ROUTE HANDLER",
        "trust": "Public HTTP endpoint.",
        "risk": (
            "Flask does not enforce auth by default. Every route must "
            "check authorization explicitly. Verify input validation and "
            "template rendering safety."
        ),
    },
    "mcp_tool": {
        "label": "MCP TOOL (callable by AI agents)",
        "trust": "Callable by LLM agents — treat all parameters as untrusted.",
        "risk": (
            "MCP tools that accept file paths, shell commands, or code are "
            "high risk. Validate paths against allow-lists. Never pass "
            "parameters to subprocess or eval without sanitization."
        ),
    },
    "cli_script": {
        "label": "CLI SCRIPT / ENTRYPOINT",
        "trust": "Runs with user's local permissions.",
        "risk": (
            "If this reads config files or environment, check for injection "
            "via malicious config values. Check subprocess calls."
        ),
    },
    "settings": {
        "label": "CONFIGURATION / SETTINGS",
        "trust": "Defines application security posture.",
        "risk": (
            "Hardcoded secrets, DEBUG=True, ALLOWED_HOSTS=['*'], missing "
            "security headers, and permissive CORS are all critical here."
        ),
    },
    "model": {
        "label": "DATA MODEL / ORM",
        "trust": "Defines data layer. Runs server-side.",
        "risk": (
            "Check for mass assignment (accepting arbitrary fields from input), "
            "missing field-level access control, and sensitive data exposure."
        ),
    },
    "test": {
        "label": "TEST FILE",
        "trust": "Not deployed. Low risk.",
        "risk": (
            "Reduce severity of findings. Check for hardcoded test "
            "credentials that match production."
        ),
    },
    "lib": {
        "label": "LIBRARY / UTILITY",
        "trust": "Depends on callers.",
        "risk": "Check if this handles user input. Trace callers to determine trust level.",
    },
}


def classify_python_file(file_path: str, content: str) -> str:
    """Classify a Python file by its role in the application.

    Returns one of the keys in PYTHON_FILE_CONTEXT.
    """
    path_lower = file_path.lower()
    name = path_lower.rsplit("/", 1)[-1] if "/" in path_lower else path_lower

    # Test files
    if name.startswith("test_") or name.startswith("conftest") or "/tests/" in path_lower:
        return "test"

    # Settings/config
    if name in ("settings.py", "config.py", "conf.py", ".env"):
        return "settings"

    # Models
    if name == "models.py" or "/models/" in path_lower:
        return "model"

    # Content-based detection
    first_2k = content[:2000]

    if "@mcp.tool" in first_2k or "FastMCP" in first_2k:
        return "mcp_tool"
    if "@app.get" in first_2k or "@app.post" in first_2k or "FastAPI" in first_2k:
        return "fastapi_route"
    is_django = "django" in first_2k.lower() or "@login_required" in first_2k
    if "def " in first_2k and "request" in first_2k and is_django:
        return "django_view"
    if "@app.route" in first_2k or "Flask(" in first_2k:
        return "flask_route"
    if "argparse" in first_2k or "click.command" in first_2k or 'if __name__' in first_2k:
        return "cli_script"

    return "lib"


def build_python_file_context(
    file_path: str,
    content: str,
    file_type: str | None = None,
) -> str:
    """Build LLM user message with file-type context for Python files."""
    if file_type is None:
        file_type = classify_python_file(file_path, content)

    ctx = PYTHON_FILE_CONTEXT.get(file_type, PYTHON_FILE_CONTEXT["lib"])
    label = ctx["label"]
    trust = ctx["trust"]
    risk = ctx["risk"]

    return (
        f"File: {file_path}\n"
        f"Type: {label}\n"
        f"Trust: {trust}\n"
        f"Risk: {risk}\n\n"
        f"```\n{content}\n```"
    )


SCAN_FUNCTION_SCHEMA = {
    "name": "report_findings",
    "description": "Report security vulnerabilities found in the analyzed code.",
    "parameters": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "owasp_category": {
                            "type": "string",
                            "enum": [
                                "A01", "A02", "A03", "A04", "A05",
                                "A06", "A07", "A08", "A09", "A10",
                            ],
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "suggested_fix": {"type": "string"},
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                    },
                    "required": [
                        "owasp_category", "severity", "title",
                        "description", "line_number", "suggested_fix",
                        "confidence",
                    ],
                },
            },
        },
        "required": ["findings"],
    },
}

# ── Triage ─────────────────────────────────────────────────────────────────

TRIAGE_SYSTEM_PROMPT = """\
You are a security triage expert. You will receive a list of potential \
security findings detected by a regex-based scanner, along with the \
surrounding code context.

For each finding, determine:
1. Is this a true positive (real vulnerability in this context)?
2. Is this a false positive (not actually exploitable here)?
3. Does it need further investigation?

Consider:
- Is the flagged code in a test file, fixture, or example? → likely false positive
- Is the flagged pattern used safely (e.g., parameterized query despite string building)?
- Is the severity appropriate for this context?
"""

TRIAGE_FUNCTION_SCHEMA = {
    "name": "report_triage",
    "description": "Report triage assessment for each finding.",
    "parameters": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "verdict": {
                            "type": "string",
                            "enum": [
                                "true_positive",
                                "false_positive",
                                "needs_investigation",
                            ],
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "reasoning": {"type": "string"},
                        "adjusted_severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                    },
                    "required": [
                        "finding_id", "verdict", "confidence", "reasoning",
                    ],
                },
            },
        },
        "required": ["assessments"],
    },
}
