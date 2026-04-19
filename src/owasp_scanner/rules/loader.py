"""Load custom scanning rules from YAML files.

Users can drop YAML rule files into ~/.owasp-scanner/rules/ to add
organization-specific patterns. Each YAML file defines one or more rules.

Example YAML rule file (~/.owasp-scanner/rules/custom.yaml):

    rules:
      - id: CUSTOM-001
        owasp_category: A07
        severity: critical
        title: Internal API key pattern
        description: Detected an internal API key that should not be in source.
        pattern: "INTERNAL_KEY_[A-Z0-9]{32}"
        file_glob: "*"
        suggested_fix: Remove the key and load from environment variables.
"""

from __future__ import annotations

import re
from pathlib import Path

from owasp_scanner.rules.patterns import Rule

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def load_rules_from_yaml(yaml_path: Path) -> list[Rule]:
    """Load rules from a single YAML file."""
    if not _HAS_YAML:
        return []

    content = yaml_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if not data or "rules" not in data:
        return []

    rules: list[Rule] = []
    for entry in data["rules"]:
        try:
            flags = re.IGNORECASE | re.MULTILINE
            exclude_pat = entry.get("exclude_pattern")
            exclude_compiled = re.compile(exclude_pat, flags) if exclude_pat else None
            rules.append(Rule(
                id=entry["id"],
                owasp_category=entry["owasp_category"],
                severity=entry["severity"],
                title=entry["title"],
                description=entry["description"],
                pattern=re.compile(entry["pattern"], flags),
                file_glob=entry.get("file_glob", "*.py"),
                suggested_fix=entry.get("suggested_fix", ""),
                exclude_pattern=exclude_compiled,
            ))
        except (KeyError, re.error):
            # Skip malformed rules silently
            continue

    return rules


def load_plugin_rules(plugins_dir: Path | None = None) -> list[Rule]:
    """Load all YAML rule files from the plugins directory.

    Args:
        plugins_dir: Directory to scan for YAML files.
                     Defaults to ~/.owasp-scanner/rules/
    """
    if not _HAS_YAML:
        return []

    if plugins_dir is None:
        plugins_dir = Path.home() / ".owasp-scanner" / "rules"

    if not plugins_dir.is_dir():
        return []

    rules: list[Rule] = []
    for yaml_file in sorted(plugins_dir.glob("*.yaml")):
        rules.extend(load_rules_from_yaml(yaml_file))
    for yml_file in sorted(plugins_dir.glob("*.yml")):
        rules.extend(load_rules_from_yaml(yml_file))

    return rules
