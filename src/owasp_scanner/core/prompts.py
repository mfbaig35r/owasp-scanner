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
