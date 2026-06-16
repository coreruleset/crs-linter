"""Tests for the no_negated_request_cookies rule checker."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    # Valid rule without negated REQUEST_COOKIES
    ('''SecRule REQUEST_COOKIES:session_id "@rx ^[a-f0-9]+$" \\
    "id:1,\\
    phase:2,\\
    pass,\\
    t:none"''', 0, "no negated REQUEST_COOKIES"),

    # Valid rule with other variables
    ('''SecRule ARGS|REQUEST_HEADERS "@rx attack" \\
    "id:2,\\
    phase:2,\\
    block,\\
    t:none"''', 0, "no REQUEST_COOKIES at all"),

    # Rule with negated REQUEST_COOKIES - should fail
    ('''SecRule !REQUEST_COOKIES:session_id|ARGS "@rx attack" \\
    "id:3,\\
    phase:2,\\
    block,\\
    t:none"''', 1, "negated REQUEST_COOKIES target"),

    # Rule with only negated REQUEST_COOKIES
    ('''SecRule !REQUEST_COOKIES "@rx .*" \\
    "id:4,\\
    phase:2,\\
    block,\\
    t:none"''', 1, "only negated REQUEST_COOKIES"),

    # Multiple rules, one with negated REQUEST_COOKIES
    ('''SecRule ARGS "@rx attack" \\
    "id:5,\\
    phase:2,\\
    block,\\
    t:none"

SecRule !REQUEST_COOKIES:token|ARGS "@rx malicious" \\
    "id:6,\\
    phase:2,\\
    block,\\
    t:none"''', 1, "one rule has negated REQUEST_COOKIES"),

    # Multiple rules with negated REQUEST_COOKIES
    ('''SecRule !REQUEST_COOKIES:session "@rx foo" \\
    "id:7,\\
    phase:2,\\
    block,\\
    t:none"

SecRule !REQUEST_COOKIES:token "@rx bar" \\
    "id:8,\\
    phase:2,\\
    block,\\
    t:none"''', 2, "multiple rules with negated REQUEST_COOKIES"),

    # Valid rule with negated other variables (not REQUEST_COOKIES)
    ('''SecRule !ARGS:safe_param|REQUEST_BODY "@rx attack" \\
    "id:9,\\
    phase:2,\\
    block,\\
    t:none"''', 0, "negated ARGS but not REQUEST_COOKIES"),

    # Negated REQUEST_COOKIES with specific cookie name
    ('''SecRule !REQUEST_COOKIES:PHPSESSID|ARGS "@rx injection" \\
    "id:10,\\
    phase:2,\\
    block,\\
    t:none"''', 1, "negated REQUEST_COOKIES with specific name"),

    # Case sensitivity check - REQUEST_COOKIES should match case-insensitively
    ('''SecRule !request_cookies:session|ARGS "@rx attack" \\
    "id:11,\\
    phase:2,\\
    block,\\
    t:none"''', 1, "lowercase request_cookies"),

    # SecAction should not be affected (only SecRule)
    ('''SecAction \\
    "id:12,\\
    phase:1,\\
    pass,\\
    nolog,\\
    setvar:tx.foo=1"''', 0, "SecAction has no targets"),

    # Chained rule with negated REQUEST_COOKIES
    ('''SecRule !REQUEST_COOKIES:session|ARGS "@rx attack" \\
    "id:13,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule REQUEST_HEADERS:User-Agent "@rx bot"''', 1, "chained rule with negated REQUEST_COOKIES"),

    # Multiple variables including REQUEST_COOKIES but not negated
    ('''SecRule REQUEST_COOKIES:session|ARGS|REQUEST_HEADERS "@rx attack" \\
    "id:14,\\
    phase:2,\\
    block,\\
    t:none"''', 0, "REQUEST_COOKIES present but not negated"),
])
def test_negated_request_cookies(run_linter, rule, expected_count, description):
    """Test detection of negated REQUEST_COOKIES targets in rules."""
    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"

    # Verify error message content
    if expected_count > 0:
        for problem in problems:
            assert "request_cookies" in problem.desc.lower(), \
                f"Error message should mention REQUEST_COOKIES: {problem.desc}"
            assert "secruleupdatetargetbyid" in problem.desc.lower(), \
                f"Error message should mention SecRuleUpdateTargetById: {problem.desc}"


def test_negated_request_cookies_error_includes_rule_id(run_linter):
    """Test that negated REQUEST_COOKIES errors include the rule ID."""
    rule = '''SecRule !REQUEST_COOKIES:session|ARGS "@rx attack" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    t:none"'''

    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    assert len(problems) == 1
    assert "942100" in problems[0].desc, \
        "Error message should include the rule ID"


def test_multiple_negated_cookies_in_same_rule(run_linter):
    """Test that only one error is reported per rule, even with multiple negated REQUEST_COOKIES."""
    rule = '''SecRule !REQUEST_COOKIES:session|!REQUEST_COOKIES:token|ARGS "@rx attack" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"'''

    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    # Should only report once per rule
    assert len(problems) == 1, \
        "Should report only once per rule even with multiple negated REQUEST_COOKIES"


def test_valid_rules_without_cookies(run_linter):
    """Test that rules without any REQUEST_COOKIES variables pass."""
    rule = '''SecRule ARGS|REQUEST_HEADERS|REQUEST_BODY "@rx attack" \\
    "id:1002,\\
    phase:2,\\
    block,\\
    t:none"'''

    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    assert len(problems) == 0, \
        "Rules without REQUEST_COOKIES should pass"


def test_chained_rules_all_valid(run_linter):
    """Test that chained rules without negated REQUEST_COOKIES pass."""
    rule = '''SecRule REQUEST_COOKIES:session "@rx ^[a-f0-9]+$" \\
    "id:1003,\\
    phase:2,\\
    pass,\\
    t:none,\\
    chain"
    SecRule ARGS:action "@streq login"'''

    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    assert len(problems) == 0, \
        "Chained rules with non-negated REQUEST_COOKIES should pass"


def test_negated_cookies_in_second_chained_rule(run_linter):
    """Test detection of negated REQUEST_COOKIES in chained rules."""
    rule = '''SecRule ARGS "@rx attack" \\
    "id:1004,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule !REQUEST_COOKIES:safe_cookie|REQUEST_HEADERS "@rx malicious"'''

    problems = run_linter(rule, rule_type="no_negated_request_cookies")

    assert len(problems) == 1, \
        "Negated REQUEST_COOKIES in chained rule should be detected"
