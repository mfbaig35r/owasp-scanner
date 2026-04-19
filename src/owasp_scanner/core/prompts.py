"""System prompts and function schemas for LLM-powered scanning."""

from __future__ import annotations

# ── Scanning ───────────────────────────────────────────────────────────────

SCAN_SYSTEM_PROMPT = """\
You are a security auditor specializing in the OWASP Top 10 (2025).
Analyze the provided source code for security vulnerabilities.

Focus especially on issues that pattern matching cannot detect:
- A01 Broken Access Control: missing authorization checks, IDOR, object-level access gaps
- A02 Security Misconfiguration: unsafe defaults, missing headers, exposed debug info
- A03 Supply Chain: unpinned deps, malicious patterns, unsafe imports
- A04 Cryptographic Failures: weak hashing, missing encryption, hardcoded keys
- A05 Injection: SQL/NoSQL/command/template injection, unsafe deserialization
- A06 Insecure Design: missing rate limiting, client-only validation, no threat model
- A07 Authentication Failures: custom auth, weak sessions, no brute-force protection
- A08 Integrity Failures: missing SRI, unsigned artifacts
- A09 Logging Failures: missing security logging, log injection, sensitive data in logs
- A10 Exception Handling: silent error swallowing, leaked stack traces, missing transactions

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

# ── Dataflow Evaluation ────────────────────────────────────────────────────

DATAFLOW_SYSTEM_PROMPT = """\
You are a security engineer evaluating data flow paths for exploitability.

You will receive:
1. Taint flow paths identified by static analysis (source → calls → sink)
2. The relevant source code for each file in the flow

For each flow, determine:
- Is this flow actually exploitable? Can an attacker control the input?
- Is there sanitization the static analyzer missed?
- What is the real-world impact if exploited?
- Are there additional flows the static analyzer might have missed?

Pay special attention to:
- Tainted data entering list/tuple literals then passed to subprocess
- F-strings containing tainted data used in shell commands
- Conditional expressions that may or may not pass tainted data
"""

DATAFLOW_FUNCTION_SCHEMA = {
    "name": "report_dataflow_assessment",
    "description": "Report exploitability assessment for each data flow.",
    "parameters": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "flow_index": {"type": "integer"},
                        "exploitable": {"type": "boolean"},
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "reasoning": {"type": "string"},
                        "impact": {"type": "string"},
                        "missed_sanitizer": {"type": "boolean"},
                    },
                    "required": [
                        "flow_index", "exploitable", "confidence",
                        "reasoning", "impact",
                    ],
                },
            },
            "additional_flows": {
                "type": "array",
                "description": "Flows the static analyzer missed.",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "source_file": {"type": "string"},
                        "source_line": {"type": "integer"},
                        "sink_file": {"type": "string"},
                        "sink_line": {"type": "integer"},
                        "sink_type": {"type": "string"},
                    },
                    "required": ["description"],
                },
            },
        },
        "required": ["assessments"],
    },
}

# ── Test Quality ───────────────────────────────────────────────────────

TEST_QUALITY_SYSTEM_PROMPT = """\
You are a test quality auditor. You will receive a source file and its \
corresponding test file(s). Analyze the test coverage and identify gaps.

For each public function/method in the source file:
1. Does a corresponding test exist?
2. How many code paths does the function have?
3. How many of those paths are exercised by tests?
4. What edge cases are missing?
5. Is the test actually testing behavior, or just calling the function?

For Rust: check unsafe blocks, .unwrap(), enum variants, error paths, generics.
For PyO3: check Python API tests, dtype conversions, error messages, GIL release.

Assign confidence 0.0-1.0. Severity: critical (no tests), high (missing error \
path), medium (missing edge case), low (style issue).
"""

TEST_QUALITY_FUNCTION_SCHEMA = {
    "name": "report_test_quality",
    "description": "Report test quality findings.",
    "parameters": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "enum": [
                                "TQ01", "TQ02", "TQ03", "TQ04", "TQ05",
                                "TQ06", "TQ07", "TQ08", "TQ09", "TQ10",
                            ],
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "source_function": {"type": "string"},
                        "suggested_test": {"type": "string"},
                        "confidence": {
                            "type": "number", "minimum": 0, "maximum": 1,
                        },
                    },
                    "required": [
                        "category", "severity", "title",
                        "description", "confidence",
                    ],
                },
            },
        },
        "required": ["findings"],
    },
}

SUGGEST_TESTS_SYSTEM_PROMPT = """\
You are a test engineer. Given a source file, identify untested functions \
and generate test skeletons with meaningful assertions. For Python: pytest \
functions. For Rust: #[test] functions with assert!/assert_eq!.
"""

SUGGEST_TESTS_FUNCTION_SCHEMA = {
    "name": "suggest_tests",
    "description": "Generate test skeletons for untested code.",
    "parameters": {
        "type": "object",
        "properties": {
            "suggestions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string"},
                        "test_code": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["function_name", "test_code", "rationale"],
                },
            },
        },
        "required": ["suggestions"],
    },
}


def build_test_quality_context(
    source_path: str,
    source_content: str,
    test_path: str | None,
    test_content: str | None,
    language: str = "python",
) -> str:
    """Build LLM user message with source + test file context."""
    msg = f"Source File: {source_path}\nLanguage: {language}\n\n"
    msg += f"SOURCE:\n```\n{source_content[:30000]}\n```\n\n"
    if test_path and test_content:
        msg += f"Test File: {test_path}\n\nTESTS:\n```\n{test_content[:30000]}\n```"
    else:
        msg += "Test File: NOT FOUND\n"
    return msg
