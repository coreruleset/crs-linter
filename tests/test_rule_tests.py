"""Tests for the rule_tests checker."""

import pytest


def test_rule_with_test_case_passes(run_linter):
    """Test that rules with test cases pass the check."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none,\\
    tag:OWASP_CRS"'''

    # Provide test_cases dict showing this rule has tests
    test_cases = {942100: True}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 0, \
        "Rules with test cases should pass"


def test_rule_without_test_case_fails(run_linter):
    """Test that rules without test cases are detected."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none,\\
    tag:OWASP_CRS"'''

    # No test cases provided
    test_cases = {}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 1, \
        "Rules without test cases should be detected"
    assert "942100" in problems[0].desc, \
        "Error should mention the rule ID"


def test_paranoia_level_control_rules_are_skipped(run_linter):
    """Test that PL control rules (ID % 1000 < 100) are skipped."""
    # Rule IDs where (ID % 1000) < 100 are PL control rules
    rule = '''SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" \\
    "id:942013,\\
    phase:1,\\
    pass,\\
    nolog,\\
    skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"'''

    # No test cases provided
    test_cases = {}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 0, \
        "PL control rules should be skipped"


@pytest.mark.parametrize("rule_id,should_skip,description", [
    (942099, True, "942099 % 1000 = 99, should be skipped"),
    (942100, False, "942100 % 1000 = 100, should NOT be skipped"),
    (942199, False, "942199 % 1000 = 199, should NOT be skipped"),
    (901013, True, "901013 % 1000 = 13, should be skipped"),
    (920100, False, "920100 % 1000 = 100, should NOT be skipped"),
    (949099, True, "949099 % 1000 = 99, should be skipped"),
])
def test_paranoia_level_threshold(run_linter, rule_id, should_skip, description):
    """Test the PL control rule threshold logic."""
    rule = f'''SecRule ARGS "@rx test" \\
    "id:{rule_id},\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}  # No test cases

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    if should_skip:
        assert len(problems) == 0, f"{description} - should not require tests"
    else:
        assert len(problems) == 1, f"{description} - should require tests"


def test_exclusion_list_full_id(run_linter):
    """Test that rules in the exclusion list are skipped (full ID match)."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}
    exclusion_list = ["942100"]  # Exclude this specific rule

    problems = run_linter(
        rule,
        rule_type="rule_tests",
        test_cases=test_cases,
        exclusion_list=exclusion_list
    )

    assert len(problems) == 0, \
        "Rules in exclusion list should be skipped"


def test_exclusion_list_prefix_match(run_linter):
    """Test that exclusion list supports prefix matching."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942150,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack" \\
    "id:942180,\\
    phase:2,\\
    block,\\
    t:none"

SecRule REQUEST_HEADERS "@rx evil" \\
    "id:943100,\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}
    exclusion_list = ["9421"]  # Exclude all rules starting with 9421

    problems = run_linter(
        rule,
        rule_type="rule_tests",
        test_cases=test_cases,
        exclusion_list=exclusion_list
    )

    # Should only flag 943100 (not in exclusion)
    assert len(problems) == 1, \
        "Only rules not matching exclusion prefix should be flagged"
    assert "943100" in problems[0].desc


def test_multiple_rules_mixed_with_and_without_tests(run_linter):
    """Test checking multiple rules with mixed test coverage."""
    rule = '''SecRule ARGS "@rx attack1" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack2" \\
    "id:942150,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack3" \\
    "id:942200,\\
    phase:2,\\
    block,\\
    t:none"'''

    # Only 942100 and 942200 have tests
    test_cases = {942100: True, 942200: True}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 1, \
        "Should detect only the rule without tests"
    assert "942150" in problems[0].desc


def test_secaction_not_checked(run_linter):
    """Test that SecAction directives are not checked (only SecRule)."""
    rule = '''SecAction \\
    "id:901100,\\
    phase:1,\\
    pass,\\
    nolog,\\
    setvar:tx.test=1"'''

    test_cases = {}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 0, \
        "SecAction should not be checked for tests"


def test_rules_without_id_are_skipped(run_linter):
    """Test that rules without IDs are skipped."""
    rule = '''SecRule ARGS "@rx attack" \\
    "phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 0, \
        "Rules without IDs should be skipped"


def test_chained_rules_with_tests(run_linter):
    """Test that chained rules with tests pass."""
    rule = '''SecRule ARGS "@rx attack" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule ARGS "@rx malicious" \\
    "t:lowercase"'''

    test_cases = {942100: True}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 0, \
        "Chained rules with tests should pass"


def test_chained_rules_without_tests(run_linter):
    """Test that chained rules without tests are detected."""
    rule = '''SecRule ARGS "@rx attack" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule ARGS "@rx malicious" \\
    "t:lowercase"'''

    test_cases = {}

    problems = run_linter(rule, rule_type="rule_tests", test_cases=test_cases)

    assert len(problems) == 1, \
        "Chained rules without tests should be detected"


def test_none_test_cases_defaults_to_empty_dict(run_linter):
    """Test that None test_cases is handled gracefully."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"'''

    # Pass None explicitly (default behavior)
    problems = run_linter(rule, rule_type="rule_tests", test_cases=None)

    assert len(problems) == 1, \
        "None test_cases should be treated as empty dict"


def test_none_exclusion_list_defaults_to_empty_list(run_linter):
    """Test that None exclusion_list is handled gracefully."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}
    # Pass None explicitly (default behavior)
    problems = run_linter(
        rule,
        rule_type="rule_tests",
        test_cases=test_cases,
        exclusion_list=None
    )

    assert len(problems) == 1, \
        "None exclusion_list should be treated as empty list"


def test_empty_exclusion_list(run_linter):
    """Test with empty exclusion list."""
    rule = '''SecRule REQUEST_URI "@rx malicious" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}
    exclusion_list = []

    problems = run_linter(
        rule,
        rule_type="rule_tests",
        test_cases=test_cases,
        exclusion_list=exclusion_list
    )

    assert len(problems) == 1, \
        "Empty exclusion list should not exclude any rules"


def test_multiple_exclusion_prefixes(run_linter):
    """Test multiple exclusion prefixes."""
    rule = '''SecRule ARGS "@rx attack1" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack2" \\
    "id:943100,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack3" \\
    "id:944100,\\
    phase:2,\\
    block,\\
    t:none"'''

    test_cases = {}
    exclusion_list = ["9421", "9431"]  # Exclude 942xxx and 943xxx

    problems = run_linter(
        rule,
        rule_type="rule_tests",
        test_cases=test_cases,
        exclusion_list=exclusion_list
    )

    # Should only flag 944100
    assert len(problems) == 1
    assert "944100" in problems[0].desc
