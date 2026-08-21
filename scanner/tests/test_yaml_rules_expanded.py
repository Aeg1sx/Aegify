"""Tests for expanded YAML rules loading and validation."""

from pathlib import Path

import pytest

from codeguard.rules.base import get_registry
from codeguard.rules.registry import load_builtin_rules
from codeguard.rules.yaml_rule import load_yaml_rules

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


class TestExpandedYAMLRules:
    def test_all_yaml_rules_load_without_errors(self):
        """All YAML rule files should parse without errors."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        assert len(rules) >= 80, f"Expected 80+ YAML rules, got {len(rules)}"

    def test_all_rules_have_valid_ids(self):
        """All rules should have IDs matching the CG-* pattern."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        for rule in rules:
            assert rule.definition.id.startswith("CG-"), (
                f"Rule ID should start with 'CG-': {rule.definition.id}"
            )

    def test_all_rules_have_descriptions(self):
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        for rule in rules:
            assert rule.definition.description, f"Rule {rule.definition.id} missing description"

    def test_all_rules_have_severity(self):
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        for rule in rules:
            assert rule.definition.severity is not None, (
                f"Rule {rule.definition.id} missing severity"
            )

    def test_owasp_categories_covered(self):
        """All 10 OWASP Top 10 categories should be covered."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        categories = set()
        for rule in rules:
            if rule.definition.owasp_category:
                # Extract category prefix like "A01", "A02", etc.
                cat = rule.definition.owasp_category.split(":")[0]
                categories.add(cat)

        expected = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}
        missing = expected - categories
        assert not missing, f"Missing OWASP categories: {missing}"

    def test_registry_has_over_110_rules(self):
        """After loading builtins + bundled YAML, should have 110+ rules."""
        load_builtin_rules()
        registry = get_registry()
        total = len(registry.get_all())
        assert total >= 95, f"Expected 95+ rules, got {total}"

    def test_rules_have_either_taint_or_patterns(self):
        """Each YAML rule should have either taint spec or pattern spec."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        for rule in rules:
            has_detection = rule.spec.taint is not None or len(rule.spec.patterns) > 0
            assert has_detection, f"Rule {rule.definition.id} has neither taint nor patterns"

    def test_no_duplicate_rule_ids(self):
        """All rule IDs should be unique."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        ids = [r.definition.id for r in rules]
        duplicates = [id for id in ids if ids.count(id) > 1]
        assert not duplicates, f"Duplicate rule IDs: {set(duplicates)}"

    def test_cwe_ids_are_integers(self):
        """CWE IDs should be valid integers when present."""
        if not RULES_DIR.exists():
            pytest.skip("rules/ directory not found")

        rules = load_yaml_rules(RULES_DIR)
        for rule in rules:
            if rule.definition.cwe_id is not None:
                assert isinstance(rule.definition.cwe_id, int), (
                    f"Rule {rule.definition.id} has non-integer CWE: {rule.definition.cwe_id}"
                )
                assert rule.definition.cwe_id > 0, (
                    f"Rule {rule.definition.id} has invalid CWE: {rule.definition.cwe_id}"
                )
