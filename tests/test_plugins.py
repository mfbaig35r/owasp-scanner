"""Tests for YAML rule plugins."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.scanner import scan_file_content
from owasp_scanner.rules.loader import load_plugin_rules, load_rules_from_yaml
from owasp_scanner.rules.patterns import get_rules


class TestLoadRulesFromYaml:
    def test_load_valid_rules(self, tmp_path: Path):
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text("""
rules:
  - id: CUSTOM-001
    owasp_category: A07
    severity: critical
    title: Internal API key pattern
    description: Detected an internal API key.
    pattern: "INTERNAL_KEY_[A-Z0-9]{32}"
    file_glob: "*"
    suggested_fix: Remove the key.
  - id: CUSTOM-002
    owasp_category: A02
    severity: medium
    title: Debug flag in config
    description: Debug flag found.
    pattern: "APP_DEBUG\\\\s*=\\\\s*true"
""")
        rules = load_rules_from_yaml(yaml_file)
        assert len(rules) == 2
        assert rules[0].id == "CUSTOM-001"
        assert rules[0].file_glob == "*"
        assert rules[1].id == "CUSTOM-002"
        assert rules[1].file_glob == "*.py"  # default

    def test_load_empty_yaml(self, tmp_path: Path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")
        rules = load_rules_from_yaml(yaml_file)
        assert len(rules) == 0

    def test_load_yaml_no_rules_key(self, tmp_path: Path):
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("something_else: true")
        rules = load_rules_from_yaml(yaml_file)
        assert len(rules) == 0

    def test_malformed_rule_skipped(self, tmp_path: Path):
        yaml_file = tmp_path / "bad_rules.yaml"
        yaml_file.write_text("""
rules:
  - id: GOOD-001
    owasp_category: A05
    severity: high
    title: Good rule
    description: Valid
    pattern: "badpattern"
  - id: BAD-NO-CATEGORY
    severity: high
    title: Missing category
    description: Invalid
    pattern: "x"
""")
        rules = load_rules_from_yaml(yaml_file)
        assert len(rules) == 1
        assert rules[0].id == "GOOD-001"


class TestLoadPluginRules:
    def test_load_from_directory(self, tmp_path: Path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yaml").write_text("""
rules:
  - id: PLUGIN-001
    owasp_category: A07
    severity: high
    title: Plugin rule
    description: From plugin
    pattern: "PLUGIN_SECRET"
""")
        rules = load_plugin_rules(rules_dir)
        assert len(rules) == 1
        assert rules[0].id == "PLUGIN-001"

    def test_empty_directory(self, tmp_path: Path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules = load_plugin_rules(rules_dir)
        assert len(rules) == 0

    def test_nonexistent_directory(self, tmp_path: Path):
        rules = load_plugin_rules(tmp_path / "nonexistent")
        assert len(rules) == 0

    def test_yml_extension_supported(self, tmp_path: Path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "extra.yml").write_text("""
rules:
  - id: YML-001
    owasp_category: A02
    severity: low
    title: YML rule
    description: From .yml file
    pattern: "YML_PATTERN"
""")
        rules = load_plugin_rules(rules_dir)
        assert len(rules) == 1


class TestPluginIntegration:
    def test_get_rules_includes_plugins(self, tmp_path: Path):
        from unittest.mock import patch

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yaml").write_text("""
rules:
  - id: INT-001
    owasp_category: A07
    severity: critical
    title: Integration test rule
    description: Should appear in get_rules
    pattern: "INTEGRATION_TEST_PATTERN"
""")
        with patch(
            "owasp_scanner.rules.loader.load_plugin_rules",
            wraps=lambda d=None: load_plugin_rules(rules_dir),
        ):
            rules = get_rules()
            rule_ids = [r.id for r in rules]
            assert "INT-001" in rule_ids

    def test_plugin_rules_actually_scan(self, tmp_path: Path):

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yaml").write_text("""
rules:
  - id: SCAN-001
    owasp_category: A07
    severity: critical
    title: Custom secret
    description: Found a custom secret
    pattern: "MY_COMPANY_KEY_[A-Z0-9]{16}"
    file_glob: "*"
""")
        plugin_rules = load_plugin_rules(rules_dir)
        code = "config = MY_COMPANY_KEY_ABCDEF1234567890"
        matches = scan_file_content(code, "config.txt", rules=plugin_rules)
        assert len(matches) == 1
        assert matches[0].rule.id == "SCAN-001"

    def test_duplicate_ids_not_added(self, tmp_path: Path):
        """Plugin rules with IDs matching built-in rules are skipped."""
        from unittest.mock import patch

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "dup.yaml").write_text("""
rules:
  - id: A05-001
    owasp_category: A05
    severity: low
    title: Duplicate of built-in
    description: Should not be added
    pattern: "duplicate"
""")
        with patch(
            "owasp_scanner.rules.loader.load_plugin_rules",
            wraps=lambda d=None: load_plugin_rules(rules_dir),
        ):
            rules = get_rules()
            a05_001 = [r for r in rules if r.id == "A05-001"]
            # Should only have the built-in version (severity=critical)
            assert len(a05_001) == 1
            assert a05_001[0].severity == "critical"
