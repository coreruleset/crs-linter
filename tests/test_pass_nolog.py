"""Tests for the pass_nolog rule checker."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    # Valid: pass with nolog
    ('''SecRule ARGS "@rx foo" \\
    "id:1,\\
    phase:2,\\
    pass,\\
    t:none,\\
    nolog"''', 0, "pass with nolog is valid"),

    # Invalid: pass without nolog
    ('''SecRule ARGS "@rx foo" \\
    "id:2,\\
    phase:2,\\
    pass,\\
    t:none"''', 1, "pass without nolog should fail"),

    # Valid: blocking rule with no nolog (not pass)
    ('''SecRule ARGS "@rx foo" \\
    "id:3,\\
    phase:2,\\
    deny,\\
    t:none"''', 0, "deny without nolog is valid"),

    # Valid: SecAction with pass and nolog
    ('''SecAction \\
    "id:4,\\
    phase:1,\\
    pass,\\
    nolog"''', 0, "SecAction with pass and nolog is valid"),

    # Invalid: SecAction with pass but no nolog
    ('''SecAction \\
    "id:5,\\
    phase:1,\\
    pass"''', 1, "SecAction with pass without nolog should fail"),

    # Multiple rules, one failing
    ('''SecRule ARGS "@rx foo" \\
    "id:6,\\
    phase:2,\\
    pass,\\
    nolog"

SecRule ARGS "@rx bar" \\
    "id:7,\\
    phase:2,\\
    pass"''', 1, "one of two rules fails"),

    # Multiple rules, both failing
    ('''SecRule ARGS "@rx foo" \\
    "id:8,\\
    phase:2,\\
    pass"

SecRule ARGS "@rx bar" \\
    "id:9,\\
    phase:2,\\
    pass"''', 2, "both rules fail"),

    # Valid: chained rule with pass and nolog
    ('''SecRule ARGS "@rx foo" \\
    "id:10,\\
    phase:2,\\
    pass,\\
    nolog,\\
    chain"
    SecRule ARGS "@rx bar" \\
    "t:none"''', 0, "chained rule with pass and nolog is valid"),
])
def test_pass_without_nolog(run_linter, rule, expected_count, description):
    """Test detection of pass action without nolog."""
    problems = run_linter(rule, rule_type="passnolog")

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"


def test_pass_nolog_error_includes_rule_id(run_linter):
    """Test that pass-without-nolog errors include the rule ID."""
    rule = '''SecRule ARGS "@rx foo" \\
    "id:123456,\\
    phase:2,\\
    pass,\\
    t:none"'''

    problems = run_linter(rule, rule_type="passnolog")

    assert len(problems) == 1
    assert "123456" in problems[0].desc, \
        "Error message should include the rule ID"


def test_pass_nolog_error_message(run_linter):
    """Test the content of pass-without-nolog error messages."""
    rule = '''SecRule ARGS "@rx foo" \\
    "id:1,\\
    phase:2,\\
    pass"'''

    problems = run_linter(rule, rule_type="passnolog")

    assert len(problems) == 1
    assert "pass" in problems[0].desc.lower(), \
        "Error message should mention 'pass'"
    assert "nolog" in problems[0].desc.lower(), \
        "Error message should mention 'nolog'"
