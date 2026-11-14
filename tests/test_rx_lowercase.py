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
    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

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

    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

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

    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

    assert len(problems) == 0


def test_rx_lowercase_is_opt_in(run_linter):
    """Without enable_checks the check does not run."""
    rule = '''SecRule ARGS "@rx foo" \\
    "id:7003,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    assert run_linter(rule, rule_type="rx_lowercase") == []


def test_rx_lowercase_scoped_flag_with_negation(run_linter):
    """(?i-s:...) enables ignorecase, so rx_lowercase leaves it to lowercase_ignorecase."""
    rule = '''SecRule ARGS "@rx (?i-s:foo)" \\
    "id:7004,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, enabled_checks=["rx_lowercase"])

    assert [p.rule for p in problems if p.rule in ("rx_lowercase", "lowercase_ignorecase")] == ["lowercase_ignorecase"]


@pytest.mark.parametrize("rule,expected_count,description", [
    ('''SecRule ARGS "@rx (?i:foo)bar" \\
    "id:7101,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 1, "partly flagged pattern is reported with a hint"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7102,\\
    phase:1,\\
    pass,\\
    capture,\\
    t:none,t:lowercase,\\
    setvar:'tx.x=%{tx.0}',\\
    nolog"''', 0, "capture needs the lowercased value"),

    ('''SecRule ARGS "@rx ^[0-9]+$" \\
    "id:7103,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "no letters in the pattern"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7104,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,t:jsDecode,\\
    nolog"''', 0, "a decoder after t:lowercase can bring upper case back"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7105,\\
    phase:1,\\
    pass,\\
    t:none,t:urlDecode,t:lowercase,\\
    nolog"''', 1, "a decoder before t:lowercase does not matter"),

    ('''SecRule ARGS "foo" \\
    "id:7106,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 1, "implicit @rx"),

    ('''SecRule ARGS "@Rx foo" \\
    "id:7107,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 1, "@Rx"),

    ('''SecRule ARGS "@rx (foo" \\
    "id:7108,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"''', 0, "unparsable pattern is left alone"),
])
def test_rx_lowercase_coverage(run_linter, rule, expected_count, description):
    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"


def test_rx_lowercase_partial_hint(run_linter):
    rule = '''SecRule ARGS "@rx (?i:foo)bar" \\
    "id:7109,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

    assert "whole pattern" in problems[0].desc


def test_rx_lowercase_rule_id_is_not_carried_over(run_linter):
    """A rule without an id is not reported under the previous rule's id."""
    rule = '''SecRule ARGS "@rx foo" \\
    "id:7110,\\
    phase:1,\\
    pass,\\
    nolog"
SecRule ARGS "@rx bar" \\
    "phase:1,\\
    pass,\\
    t:lowercase,\\
    nolog"'''

    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

    assert len(problems) == 1
    assert "7110" not in problems[0].desc


@pytest.mark.parametrize("rule,expected_count,description", [
    ('''SecRule ARGS "@rx foo" \\
    "id:7201,\\
    phase:1,\\
    pass,\\
    t:lowercase,t:none,\\
    nolog"''', 0, "t:none cancels t:lowercase"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7202,\\
    phase:1,\\
    pass,\\
    t:lowercase,t:jsDecode,t:none,t:lowercase,\\
    nolog"''', 1, "a cancelled jsDecode does not hide the report"),

    ('''SecRule ARGS "@rx union" \\
    "id:7203,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,t:removeWhitespace,\\
    nolog"''', 1, "a harmless transformation after t:lowercase"),

    ('''SecRule ARGS "@rx union" \\
    "id:7204,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,t:sqlHexDecode,\\
    nolog"''', 0, "sqlHexDecode can bring upper case back"),

    ('''SecRule ARGS "@rx union" \\
    "id:7205,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,t:md5,\\
    nolog"''', 0, "md5 depends on the case of its input"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7206,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,\\
    setvar:'tx.n=%{matched_var_name}',\\
    nolog"''', 1, "%{matched_var_name} is not the lowercased value"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7207,\\
    phase:1,\\
    pass,\\
    capture,\\
    t:none,t:lowercase,\\
    chain"
    SecRule ARGS:b "@streq %{tx.1}" \\
        "t:none"''', 0, "a later operator argument reads the capture"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7208,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,\\
    chain"
    SecRule TX:1 "@streq x" \\
        "t:none"''', 1, "TX:1 without capture does not read the lowercased value"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7209,\\
    phase:1,\\
    pass,\\
    capture,\\
    t:none,t:lowercase,\\
    chain"
    SecRule ARGS:b "@rx (bar)" \\
        "capture,t:none,chain"
    SecRule TX:1 "@streq x" \\
        "t:none"''', 1, "TX:1 after another capture is not this rule's"),

    ('''SecRule ARGS "@rx foo" \\
    "id:7210,\\
    phase:1,\\
    pass,\\
    t:none,t:lowercase,\\
    chain"
    SecRule MATCHED_VAR "@streq foo" \\
        "t:none"''', 0, "the next link reads MATCHED_VAR"),
])
def test_rx_lowercase_transformations_and_reads(run_linter, rule, expected_count, description):
    problems = run_linter(rule, rule_type="rx_lowercase", enabled_checks=["rx_lowercase"])

    assert len(problems) == expected_count, \
        f"{description}: expected {expected_count} problems, got {len(problems)}"
