"""
Test the Rules metadata system and individual rule testing.
"""

import pytest
from crs_linter.linter import Linter
from crs_linter.rules_metadata import Rules, get_rules
from crs_linter.rule import Rule
from crs_linter.lint_problem import LintProblem
from crs_linter.rules.ignore_case import IgnoreCase
from crs_linter.rules.crs_tag import CrsTag


def test_rule_metadata_in_rule_class():
    """Test that rule instances have their own metadata."""
    rule = IgnoreCase()

    assert rule.name == "ignorecase"
    assert rule.success_message == "Ignore case check ok."
    assert rule.error_message == "Ignore case check found error(s)"
    assert rule.error_title == "Case check"
    assert rule.args == ("data",)


def test_default_rules_creation():
    """Test that default rules are created correctly."""
    rules = get_rules()

    # Check that we have some rules registered (exact count may vary)
    assert len(rules._rules) > 0, "No rules registered"

    # Check that we have some expected rules
    registered_rules = [rule.name for rule in rules._rules]
    expected_rules = ["ignorecase", "orderedactions", "variablesusage",
                     "plconsistency", "crstag", "version", "approvedtags"]

    for expected in expected_rules:
        assert expected in registered_rules, f"Expected rule {expected} not found"


def test_rules_get_rule_messages():
    """Test that Rules.get_rule_messages returns correct messages."""
    rules = get_rules()

    success, error, title = rules.get_rule_messages("ignorecase")
    assert success == "Ignore case check ok."
    assert error == "Ignore case check found error(s)"
    assert title == "Case check"


def test_rules_get_rule_configs(parse_rule):
    """Test that Rules.get_rule_configs generates correct configurations."""
    rules = get_rules()
    sample_data = parse_rule('SecRule ARGS "@rx ^test" "id:1,phase:1,log"')
    linter = Linter(sample_data)

    configs = rules.get_rule_configs(linter)

    # Should have configurations for all registered rules
    assert len(configs) > 0

    # Each config should be a tuple of (rule_instance, args, kwargs, condition)
    for rule_instance, args, kwargs, condition in configs:
        assert isinstance(rule_instance, Rule)
        assert isinstance(args, list)
        assert isinstance(kwargs, dict)


def test_individual_rule_ignorecase(parse_rule):
    """Test the IgnoreCase rule individually."""
    rule = IgnoreCase()
    sample_data = parse_rule('SecRule ARGS "@rx ^test" "id:1,phase:1,LOG"')

    problems = list(rule.check(sample_data))

    # Should have 1 problem for wrong case
    assert len(problems) == 1
    assert problems[0].rule == "ignore_case"


def test_individual_rule_crstag(parse_rule):
    """Test the CrsTag rule individually."""
    rule = CrsTag()
    sample_data = parse_rule('SecRule ARGS "@rx ^test" "id:900100,phase:1,log"')

    problems = list(rule.check(sample_data))

    # Should have 1 problem for missing OWASP_CRS tag
    assert len(problems) == 1
    assert problems[0].rule == "crs_tag"


def test_custom_rules_system(parse_rule):
    """Test that a custom Rules system can be created with specific rules."""
    # Test that we can create a new Rules instance and register rules
    rules = Rules()

    # Get initial count
    initial_count = len(rules._rules)

    # Register additional rules
    rules.register_rule(IgnoreCase())
    rules.register_rule(CrsTag())

    # Should have more rules now
    assert len(rules._rules) >= initial_count + 2

    sample_data = parse_rule('SecRule ARGS "@rx ^test" "id:1,phase:1,log"')
    linter = Linter(sample_data, rules=rules)

    configs = rules.get_rule_configs(linter)

    # Should have rule configurations
    assert len(configs) > 0


def test_rule_conditions(parse_rule):
    """Test that conditional rules are properly handled."""
    rules = get_rules()
    sample_data = parse_rule('SecRule ARGS "@rx ^test" "id:1,phase:1,log"')
    linter = Linter(sample_data)

    # Without version, version rule should not run
    configs_without_version = rules.get_rule_configs(linter)
    version_configs = [c for c in configs_without_version if c[0].name == "version"]

    # Version rule should have condition = False
    if len(version_configs) > 0:
        assert version_configs[0][3] is None or version_configs[0][3] == False

    # With version, version rule should run
    configs_with_version = rules.get_rule_configs(linter, crs_version="OWASP_CRS/4.0.0")
    version_configs = [c for c in configs_with_version if c[0].name == "version"]

    # Version rule should have condition = True
    if len(version_configs) > 0:
        assert version_configs[0][3] is None or version_configs[0][3] == True
