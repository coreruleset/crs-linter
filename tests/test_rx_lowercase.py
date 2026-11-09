"""Tests for the rx_lowercase checker."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    ('''SecRule ARGS "@rx foo" \\
    "id:1,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,\\
    nolog"''', 1, "t:lowercase with @rx"),

    ('''SecRule ARGS "!@rx foo" \\
    "id:2,\\
    phase:1,\\
    pass,\\
    t:LowerCase,\\
    nolog"''', 1, "negated @rx and mixed-case transformation name"),

    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:3,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog"''', 0, "(?i) without t:lowercase"),

    ('''SecRule ARGS "@rx (?i)foo" \\
    "id:4,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "(?i) with t:lowercase is left to lowercase_ignorecase"),

    ('''SecRule ARGS "@within foo bar" \\
    "id:5,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "non-regex operators need t:lowercase"),

    ('''SecRule ARGS "@pm foo bar" \\
    "id:6,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "@pm is not checked"),
])
def test_rx_lowercase_detection(run_linter, rule, expected_count, description):
    problems = run_linter(rule, rule_type="rx_lowercase")

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"


def test_rx_lowercase_chain_link(run_linter):
    """A chained @rx link is reported with the id of its chain starter."""
    rule = '''SecRule ARGS "@streq foo" \\
    "id:7001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    chain"
    SecRule MATCHED_VAR "@rx bar" \\
        "t:lowercase"'''

    problems = run_linter(rule, rule_type="rx_lowercase")

    assert len(problems) == 1
    assert "7001" in problems[0].desc
    assert "(?i)" in problems[0].desc


def test_rx_lowercase_exemption(run_linter):
    rule = '''#crs-linter:ignore:rx_lowercase
SecRule ARGS "@rx foo" \\
    "id:7002,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="rx_lowercase")

    assert len(problems) == 0
