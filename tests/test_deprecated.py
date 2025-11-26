"""Tests for the deprecated rule checker."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    # Valid rule without deprecated patterns
    ('''SecRule TX:sql_error_match "@eq 1" \\
    "id:1,\\
    phase:4,\\
    block,\\
    capture,\\
    t:none"''', 0, "no deprecated patterns"),

    # Rule with deprecated ctl:auditLogParts
    ('''SecRule TX:sql_error_match "@eq 1" \\
    "id:2,\\
    phase:4,\\
    block,\\
    capture,\\
    t:none,\\
    ctl:auditLogParts=+E"''', 1, "ctl:auditLogParts is deprecated"),

    # Multiple rules, one with deprecated pattern
    ('''SecRule ARGS "@rx attack" \\
    "id:3,\\
    phase:2,\\
    block,\\
    t:none"

SecRule TX:anomaly_score "@ge 5" \\
    "id:4,\\
    phase:5,\\
    deny,\\
    ctl:auditLogParts=+E"''', 1, "one rule has deprecated pattern"),

    # Multiple rules, multiple deprecated patterns
    ('''SecRule ARGS "@rx attack" \\
    "id:5,\\
    phase:2,\\
    block,\\
    ctl:auditLogParts=+E"

SecRule TX:anomaly_score "@ge 5" \\
    "id:6,\\
    phase:5,\\
    deny,\\
    ctl:auditLogParts=+E"''', 2, "multiple deprecated patterns"),

    # Case insensitive check - uppercase CTL
    ('''SecRule TX:sql_error_match "@eq 1" \\
    "id:7,\\
    phase:4,\\
    block,\\
    CTL:AuditLogParts=+E"''', 1, "uppercase CTL:AuditLogParts"),

    # Case insensitive check - mixed case
    ('''SecRule TX:sql_error_match "@eq 1" \\
    "id:8,\\
    phase:4,\\
    block,\\
    CtL:auditlogparts=+E"''', 1, "mixed case CtL:auditlogparts"),

    # Valid ctl actions (not auditLogParts)
    ('''SecRule ARGS "@rx foo" \\
    "id:9,\\
    phase:2,\\
    block,\\
    ctl:ruleEngine=Off"''', 0, "valid ctl:ruleEngine action"),

    # SecAction with deprecated pattern
    ('''SecAction \\
    "id:10,\\
    phase:1,\\
    pass,\\
    nolog,\\
    ctl:auditLogParts=+E"''', 1, "SecAction with deprecated pattern"),
])
def test_deprecated_patterns(run_linter, rule, expected_count, description):
    """Test detection of deprecated patterns in rules."""
    problems = run_linter(rule, rule_type="deprecated")

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"

    # Verify error message content
    if expected_count > 0:
        for problem in problems:
            assert "auditlogparts" in problem.desc.lower(), \
                f"Error message should mention auditLogParts: {problem.desc}"


def test_deprecated_error_includes_rule_id(run_linter):
    """Test that deprecated pattern errors include the rule ID."""
    rule = '''SecRule TX:sql_error_match "@eq 1" \\
    "id:123456,\\
    phase:4,\\
    block,\\
    ctl:auditLogParts=+E"'''

    problems = run_linter(rule, rule_type="deprecated")

    assert len(problems) == 1
    assert "123456" in problems[0].desc, \
        "Error message should include the rule ID"


def test_no_deprecated_in_chained_rules(run_linter):
    """Test that rules without deprecated patterns pass even in chains."""
    rule = '''SecRule ARGS "@rx attack" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule ARGS "@rx malicious" \\
    "t:lowercase"'''

    problems = run_linter(rule, rule_type="deprecated")

    assert len(problems) == 0, \
        "Chained rules without deprecated patterns should pass"


def test_deprecated_in_second_chained_rule(run_linter):
    """Test detection of deprecated patterns in chained rules."""
    rule = '''SecRule ARGS "@rx attack" \\
    "id:1002,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule ARGS "@rx malicious" \\
    "t:lowercase,\\
    ctl:auditLogParts=+E"'''

    problems = run_linter(rule, rule_type="deprecated")

    assert len(problems) == 1, \
        "Deprecated pattern in chained rule should be detected"


def test_multiple_deprecated_in_single_rule(run_linter):
    """Test detection of multiple deprecated patterns in a single rule."""
    # Note: This is a theoretical test - in practice, you can't have multiple
    # ctl:auditLogParts in a single rule, but we test the checker's behavior
    rule = '''SecRule ARGS "@rx attack" \\
    "id:1003,\\
    phase:2,\\
    block,\\
    ctl:auditLogParts=+E"'''

    problems = run_linter(rule, rule_type="deprecated")

    assert len(problems) == 1, \
        "Should detect deprecated pattern in rule"
