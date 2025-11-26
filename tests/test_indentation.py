import pytest


# Test data for indentation tests
PROPERLY_FORMATTED_RULE = '''SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\
    "id:920100,\\
    phase:1,\\
    block,\\
    capture,\\
    t:none,\\
    t:lowercase,\\
    msg:'Bad User Agent',\\
    logdata:'Matched Data: %{MATCHED_VAR}',\\
    tag:'application-multi',\\
    tag:'language-multi',\\
    tag:'platform-multi',\\
    tag:'attack-generic',\\
    tag:'paranoia-level/1',\\
    tag:'OWASP_CRS',\\
    tag:'capec/1000/152/137',\\
    tag:'PCI/6.5.10',\\
    ver:'OWASP_CRS/4.10.0',\\
    severity:'CRITICAL',\\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"'''

BROKEN_INDENTATION_RULE = '''SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\
  "id:920100,\\
  phase:1,\\
  block,\\
  capture,\\
  t:none,\\
  t:lowercase,\\
  msg:'Bad User Agent',\\
  logdata:'Matched Data: %{MATCHED_VAR}',\\
  tag:'application-multi',\\
  tag:'language-multi',\\
  tag:'platform-multi',\\
  tag:'attack-generic',\\
  tag:'paranoia-level/1',\\
  tag:'OWASP_CRS',\\
  tag:'capec/1000/152/137',\\
  tag:'PCI/6.5.10',\\
  ver:'OWASP_CRS/4.10.0',\\
  severity:'CRITICAL',\\
  setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"'''

TRAILING_NEWLINE_RULE = '''SecRule REQUEST_URI "@beginswith /index.php" \\
    "id:1,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog"
'''

MIXED_SPACING_RULE = '''SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\
\t"id:920100,\\
    phase:1,\\
\tblock,\\
    tag:'OWASP_CRS',\\
    ver:'OWASP_CRS/4.10.0'"'''


def test_check_indentation_proper_format(run_linter):
    """Test that properly formatted CRS rules pass indentation check.

    This uses the CRS format with:
    - 4 spaces for indentation
    - Proper line continuation with backslash
    - Actions properly formatted on separate lines
    - No trailing newline (as per msc_pyparser formatter)
    """
    problems = run_linter(PROPERLY_FORMATTED_RULE, rule_type="indentation")

    assert len(problems) == 0, \
        f"Expected no indentation problems, but found: {problems}"


def test_check_indentation_broken_format(run_linter):
    """Test that improperly formatted rules are caught by indentation check.

    This test uses broken indentation with:
    - Incorrect spacing (2 spaces instead of 4)
    - Improper alignment
    """
    problems = run_linter(BROKEN_INDENTATION_RULE, rule_type="indentation")

    assert len(problems) > 0, \
        "Expected indentation problems for broken formatting"

    # Verify that the error message mentions indentation/formatting
    assert any("Indentation" in str(p.desc) for p in problems), \
        f"Expected indentation error message, got: {[p.desc for p in problems]}"


def test_check_indentation_trailing_newline(run_linter):
    """Test that rules with a trailing newline are accepted.

    The msc_pyparser formatter does not add a trailing newline,
    but most editors do. We normalize trailing newlines so that
    properly formatted files with trailing newlines pass the check.
    This matches the behavior of the official CRS files.
    """
    problems = run_linter(TRAILING_NEWLINE_RULE, rule_type="indentation")

    # Should NOT have indentation problems - trailing newlines are normalized
    assert len(problems) == 0, \
        f"Expected no indentation problems for trailing newline, but found: {problems}"


def test_check_indentation_mixed_spacing(run_linter):
    """Test that rules with mixed tabs and spaces are caught."""
    problems = run_linter(MIXED_SPACING_RULE, rule_type="indentation")

    # Should have indentation problems for mixed tabs/spaces
    assert len(problems) > 0, \
        "Expected indentation problems for mixed tabs/spaces"


@pytest.mark.parametrize("rule,should_pass,description", [
    (PROPERLY_FORMATTED_RULE, True, "properly formatted rule"),
    (BROKEN_INDENTATION_RULE, False, "2 spaces instead of 4"),
    (TRAILING_NEWLINE_RULE, True, "trailing newline"),
    (MIXED_SPACING_RULE, False, "mixed tabs and spaces"),
])
def test_indentation_parametrized(run_linter, rule, should_pass, description):
    """Parametrized test for various indentation scenarios."""
    problems = run_linter(rule, rule_type="indentation")

    if should_pass:
        assert len(problems) == 0, \
            f"Expected {description} to pass, but found problems: {problems}"
    else:
        assert len(problems) > 0, \
            f"Expected {description} to fail, but found no problems"
