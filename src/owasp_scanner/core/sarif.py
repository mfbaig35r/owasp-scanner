"""SARIF 2.1.0 export for CI/GitHub/VS Code integration."""

from __future__ import annotations

from typing import Any

from owasp_scanner.core.database import Finding
from owasp_scanner.rules.patterns import OWASP_CATEGORIES, get_rules

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def generate_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 JSON document from findings."""
    # Build rule descriptors from all known rules
    rules_map: dict[str, dict[str, Any]] = {}
    for rule in get_rules():
        rules_map[rule.id] = {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "helpUri": f"https://owasp.org/Top10/{rule.owasp_category}_2025/",
            "properties": {
                "owasp-category": rule.owasp_category,
                "severity": rule.severity,
            },
        }

    # Also add rules from findings that aren't in the built-in set (e.g. config checks)
    for f in findings:
        if f.rule_id and f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "properties": {
                    "owasp-category": f.owasp_category,
                    "severity": f.severity,
                },
            }

    # Build results
    results: list[dict[str, Any]] = []
    for f in findings:
        result: dict[str, Any] = {
            "ruleId": f.rule_id or "manual",
            "level": _SEVERITY_TO_SARIF.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": f.line_number or 1},
                    },
                },
            ],
            "properties": {
                "owasp-category": f.owasp_category,
                "owasp-label": OWASP_CATEGORIES.get(f.owasp_category, ""),
                "severity": f.severity,
                "status": f.status,
                "finding-id": f.id,
            },
        }
        if f.suggested_fix:
            result["fixes"] = [
                {"description": {"text": f.suggested_fix}},
            ]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "owasp-scanner",
                        "version": "0.1.0",
                        "informationUri": "https://owasp.org/www-project-top-ten/",
                        "rules": list(rules_map.values()),
                    },
                },
                "results": results,
            },
        ],
    }
