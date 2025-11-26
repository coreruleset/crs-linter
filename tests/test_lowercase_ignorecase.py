"""Tests for the lowercase_ignorecase checker."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    # Valid rule with t:lowercase and case-sensitive regex
    ('''SecRule ARGS "@rx foo" \\
    "id:1,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "t:lowercase with case-sensitive regex is OK"),

    # Valid rule with (?i) flag without t:lowercase
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:2,\\
    phase:1,\\
    pass,\\
    nolog"''', 0, "(?i) flag without t:lowercase is OK"),

    # Invalid: combining t:lowercase with (?i) flag
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:3,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 1, "(?i) flag with t:lowercase is redundant"),

    # Valid: t:none doesn't conflict
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:4,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog"''', 0, "t:none with (?i) is OK"),

    # Valid: other transformations don't conflict
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:5,\\
    phase:1,\\
    pass,\\
    t:urlDecode,\\
    nolog"''', 0, "t:urlDecode with (?i) is OK"),

    # Invalid: uppercase t:LOWERCASE should also be caught
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:6,\\
    phase:1,\\
    pass,\\
    t:LOWERCASE,\\
    nolog"''', 1, "t:LOWERCASE (uppercase) with (?i) is redundant"),

    # Invalid: mixed case t:LowerCase should also be caught
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:7,\\
    phase:1,\\
    pass,\\
    t:LowerCase,\\
    nolog"''', 1, "t:LowerCase (mixed) with (?i) is redundant"),

    # Valid: SecAction is not checked (only SecRule)
    ('''SecAction \\
    "id:8,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "SecAction is not checked"),

    # Invalid: Multiple transformations, one is t:lowercase
    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:9,\\
    phase:1,\\
    pass,\\
    t:urlDecode,\\
    t:lowercase,\\
    nolog"''', 1, "multiple transforms with t:lowercase and (?i)"),

    # Valid: operators other than @rx are not checked
    ('''SecRule ARGS "@eq foo" \\
    "id:10,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "operators other than @rx are not checked"),

    # Valid: @rx without (?i) flag with t:lowercase
    ('''SecRule ARGS "@rx ^foo$" \\
    "id:11,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "@rx without (?i) flag is OK"),

    # Invalid: (?i) in middle of regex
    ('''SecRule ARGS "@rx foo(?i)bar" \\
    "id:12,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "(?i) not at start is not checked"),
])
def test_lowercase_ignorecase_detection(run_linter, rule, expected_count, description):
    """Test detection of redundant t:lowercase with (?i) flag."""
    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"

    # Verify error message content
    if expected_count > 0:
        for problem in problems:
            assert "(?i)" in problem.desc and "lowercase" in problem.desc.lower(), \
                f"Error message should mention both (?i) and lowercase: {problem.desc}"


def test_lowercase_ignorecase_error_includes_rule_id(run_linter):
    """Test that error messages include the rule ID."""
    rule = '''SecRule ARGS "@rx (?i)foo" \\
    "id:123456,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 1
    assert "123456" in problems[0].desc, \
        "Error message should include the rule ID"


def test_multiple_rules_with_mixed_patterns(run_linter):
    """Test checking multiple rules with mixed valid and invalid patterns."""
    rule = '''SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    nolog"

SecRule ARGS "@rx (?i)bar" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"

SecRule ARGS "@rx baz" \\
    "id:1003,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 1, \
        "Should detect only the rule with both (?i) and t:lowercase"
    assert "1002" in problems[0].desc, \
        "Error should be for rule 1002"


def test_chained_rules_with_lowercase_ignorecase(run_linter):
    """Test detection in chained rules."""
    rule = '''SecRule ARGS "@rx (?i)foo" \\
    "id:2001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    chain"
    SecRule ARGS "@rx bar" \\
    "t:none"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 1, \
        "Should detect redundant pattern in first rule of chain"


def test_multiple_lowercase_transforms_with_ignorecase(run_linter):
    """Test rule with multiple t:lowercase transformations and (?i)."""
    rule = '''SecRule ARGS "@rx (?i)foo" \\
    "id:3001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    t:urlDecode,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    # Should catch both t:lowercase instances
    assert len(problems) == 2, \
        "Should detect both t:lowercase transformations"


def test_complex_regex_with_ignorecase_flag(run_linter):
    """Test with complex regex patterns starting with (?i)."""
    rule = '''SecRule ARGS "@rx (?i)^(GET|POST|HEAD)\\\\s+/admin" \\
    "id:4001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 1, \
        "Should detect redundant pattern even with complex regex"


def test_regex_with_other_flags_and_ignorecase(run_linter):
    """Test regex with multiple flags including (?i)."""
    rule = '''SecRule ARGS "@rx (?i)(?:foo|bar)" \\
    "id:5001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 1, \
        "Should detect redundant pattern with multiple regex flags"


def test_no_false_positives_on_valid_patterns(run_linter):
    """Test that valid patterns don't trigger false positives."""
    rule = '''SecRule ARGS "@rx foo" \\
    "id:6001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"

SecRule ARGS "@rx (?i)bar" \\
    "id:6002,\\
    phase:1,\\
    pass,\\
    t:urlDecode,\\
    nolog"

SecRule ARGS "@rx baz" \\
    "id:6003,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog"'''

    problems = run_linter(rule, rule_type="lowercase_ignorecase")

    assert len(problems) == 0, \
        "Valid patterns should not trigger any problems"
