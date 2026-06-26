"""Tests for the args_names_json_prefix rule."""

import pytest


@pytest.mark.parametrize("rule,expected_count,description", [
    # --- @rx cases ---
    # Failing: ^-anchored pattern without (?:json.)? prefix
    ('''SecRule ARGS_NAMES "@rx ^foo" \
    "id:1,phase:2,deny,t:none"''', 1, "@rx with ^ but no json prefix"),

    ('''SecRule ARGS_NAMES "@rx ^admin\\s*" \
    "id:2,phase:2,deny,t:none"''', 1, "@rx with ^ and extra chars but no json prefix"),

    ('''SecRule ARGS_NAMES "@rx ^[\\W\\d]+\\s*?select" \
    "id:3,phase:2,deny,t:none"''', 1, "@rx with ^ and character class but no json prefix"),

    # Passing: (?:json\.)? prefix present
    ('''SecRule ARGS_NAMES "@rx ^(?:json\\.)?foo" \
    "id:10,phase:2,deny,t:none"''', 0, "@rx with ^(?:json\\.)? prefix"),

    ('''SecRule ARGS_NAMES "@rx ^(?:json.)?foo" \
    "id:11,phase:2,deny,t:none"''', 0, "@rx with ^(?:json.)? prefix (unescaped dot)"),

    # Passing: not anchored to start
    ('''SecRule ARGS_NAMES "@rx foo" \
    "id:12,phase:2,deny,t:none"''', 0, "@rx without ^ anchor"),

    ('''SecRule ARGS_NAMES "@rx .*foo" \
    "id:13,phase:2,deny,t:none"''', 0, "@rx with .* prefix (not start-anchored)"),

    # --- @beginsWith cases ---
    ('''SecRule ARGS_NAMES "@beginsWith foo" \
    "id:20,phase:2,deny,t:none"''', 1, "@beginsWith always start-anchored"),

    ('''SecRule ARGS_NAMES "@beginsWith admin" \
    "id:21,phase:2,deny,t:none"''', 1, "@beginsWith with admin value"),

    # --- @streq cases ---
    ('''SecRule ARGS_NAMES "@streq username" \
    "id:30,phase:2,deny,t:none"''', 1, "@streq always full-string match"),

    ('''SecRule ARGS_NAMES "@streq file_content" \
    "id:31,phase:2,deny,t:none"''', 1, "@streq with underscore value"),

    # --- Non-ARGS_NAMES targets: should pass ---
    ('''SecRule ARGS "@rx ^foo" \
    "id:40,phase:2,deny,t:none"''', 0, "ARGS (not ARGS_NAMES) with ^ anchor"),

    ('''SecRule REQUEST_HEADERS "@rx ^foo" \
    "id:41,phase:2,deny,t:none"''', 0, "REQUEST_HEADERS with ^ anchor"),

    ('''SecRule REQUEST_URI "@beginsWith /admin" \
    "id:42,phase:2,deny,t:none"''', 0, "REQUEST_URI with @beginsWith"),

    # --- Other operators on ARGS_NAMES: should pass ---
    ('''SecRule ARGS_NAMES "@contains foo" \
    "id:50,phase:2,deny,t:none"''', 0, "@contains is not start-anchored"),

    ('''SecRule ARGS_NAMES "@pm foo bar" \
    "id:51,phase:2,deny,t:none"''', 0, "@pm is not start-anchored"),

    ('''SecRule ARGS_NAMES "@endsWith foo" \
    "id:52,phase:2,deny,t:none"''', 0, "@endsWith is not start-anchored"),

    # --- ARGS_NAMES among multiple targets ---
    ('''SecRule ARGS_NAMES|REQUEST_HEADERS "@rx ^foo" \
    "id:60,phase:2,deny,t:none"''', 1, "ARGS_NAMES in list with ^ anchor"),

    # --- Negated ARGS_NAMES: should pass (negation changes semantics) ---
    ('''SecRule !ARGS_NAMES "@rx ^foo" \
    "id:70,phase:2,deny,t:none"''', 0, "negated !ARGS_NAMES should not flag"),

    # --- SecAction (no variables): should pass ---
    ('''SecAction \
    "id:80,phase:1,pass,nolog"''', 0, "SecAction has no targets"),
])
def test_args_names_json_prefix(run_linter, rule, expected_count, description):
    """Test that ARGS_NAMES start-anchored operator checks work correctly."""
    problems = run_linter(rule, rule_type="args_names_json_prefix")

    assert len(problems) == expected_count, (
        f"{description}: expected {expected_count} problem(s), got {len(problems)}: "
        + ", ".join(p.desc for p in problems)
    )


def test_error_message_includes_rule_id(run_linter):
    """Test that error messages include the rule ID."""
    rule = '''SecRule ARGS_NAMES "@rx ^username$" \
    "id:942100,phase:2,deny,t:none"'''

    problems = run_linter(rule, rule_type="args_names_json_prefix")

    assert len(problems) == 1
    assert "942100" in problems[0].desc, (
        f"Error message should include the rule ID: {problems[0].desc}"
    )


def test_error_message_mentions_json_prefix(run_linter):
    """Test that error messages explain the json. prefix issue."""
    rule = '''SecRule ARGS_NAMES "@rx ^admin" \
    "id:1,phase:2,deny,t:none"'''

    problems = run_linter(rule, rule_type="args_names_json_prefix")

    assert len(problems) == 1
    assert "json" in problems[0].desc.lower(), (
        f"Error message should mention json prefix: {problems[0].desc}"
    )


def test_multiple_rules_flags_each(run_linter):
    """Test that each offending rule is flagged independently."""
    rule = '''SecRule ARGS_NAMES "@rx ^foo" \
    "id:1,phase:2,deny,t:none"

SecRule ARGS_NAMES "@beginsWith bar" \
    "id:2,phase:2,deny,t:none"

SecRule ARGS_NAMES "@rx ^(?:json\\.)?baz" \
    "id:3,phase:2,deny,t:none"'''

    problems = run_linter(rule, rule_type="args_names_json_prefix")

    assert len(problems) == 2, (
        f"Expected 2 problems, got {len(problems)}: "
        + ", ".join(p.desc for p in problems)
    )


def test_chained_rule_with_args_names(run_linter):
    """Test that ARGS_NAMES in a chained rule is also checked."""
    rule = '''SecRule REQUEST_METHOD "@streq POST" \
    "id:1,phase:2,deny,t:none,chain"
    SecRule ARGS_NAMES "@rx ^username$"'''

    problems = run_linter(rule, rule_type="args_names_json_prefix")

    assert len(problems) == 1, (
        f"Expected 1 problem in chained rule, got {len(problems)}"
    )
