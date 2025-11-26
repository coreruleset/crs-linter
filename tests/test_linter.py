import pytest


def test_parser(parse_rule):
    """Test basic parsing functionality."""
    rule = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    parsed = parse_rule(rule)
    assert parsed is not None


@pytest.mark.parametrize("rule,rule_type,expected_count", [
    # Ignore case tests
    ('SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"',
     "ignore_case", 0),
    ('SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,LOG,NoLOg,status:403"',
     "ignore_case", 2),

    # Action order tests
    ('SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,nolog"',
     "ordered_actions", 0),
    ('SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"',
     "ordered_actions", 1),
])
def test_basic_rule_checks(run_linter, rule, rule_type, expected_count):
    """Parametrized tests for basic rule checks."""
    problems = run_linter(rule, rule_type=rule_type)
    assert len(problems) == expected_count, \
        f"Expected {expected_count} problems, got {len(problems)}: {problems}"


def test_check_tx_variable(run_linter):
    """Test that variables are defined in the transaction."""
    rule = """SecRule &TX:blocking_paranoia_level "@eq 0" \\
    "id:901120,\\
    phase:1,\\
    pass,\\
    nolog,\\
    ver:'OWASP_CRS/4.0.0-rc1',\\
    setvar:'tx.blocking_paranoia_level=1'"

SecRule &TX:detection_paranoia_level "@eq 0" \\
    "id:901125,\\
    phase:1,\\
    pass,\\
    nolog,\\
    ver:'OWASP_CRS/4.0.0-rc1',\\
    setvar:'tx.detection_paranoia_level=%{TX.blocking_paranoia_level}'"
    """

    problems = run_linter(rule, rule_type="variables_usage")
    assert len(problems) == 0, "Should have no problems for properly defined variables"


def test_check_tx_variable_fail_nonexisting(run_linter):
    """Test that undefined variables are caught."""
    rule = """SecRule TX:foo "@rx bar" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    nolog"

SecRule ARGS "@rx ^.*$" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    nolog,\\
    setvar:tx.bar=1"
        """

    problems = run_linter(rule, rule_type="variables_usage")
    assert len(problems) == 1, "Should have 1 problem for undefined variable"


PL_CONSISTENCY_RULE_VALID = """
    SecAction \\
    "id:901200,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    tag:'OWASP_CRS',\\
    ver:'OWASP_CRS/4.11.0-dev',\\
    setvar:'tx.blocking_inbound_anomaly_score=0',\\
    setvar:'tx.detection_inbound_anomaly_score=0',\\
    setvar:'tx.inbound_anomaly_score_pl1=0',\\
    setvar:'tx.inbound_anomaly_score_pl2=0',\\
    setvar:'tx.inbound_anomaly_score_pl3=0',\\
    setvar:'tx.inbound_anomaly_score_pl4=0'"

    SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:944011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.11.0-dev',skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA"

    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\\\d+$" \\
    "id:920160,\\
    phase:1,\\
    block,\\
    t:none,\\
    tag:'paranoia-level/1',\\
    severity:'CRITICAL',\\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
    """

PL_CONSISTENCY_RULE_INVALID = """
    SecAction \\
    "id:901200,\\
    phase:1,\\
    pass,\\
    t:none,\\
    nolog,\\
    tag:'OWASP_CRS',\\
    ver:'OWASP_CRS/4.11.0-dev',\\
    setvar:'tx.blocking_inbound_anomaly_score=0',\\
    setvar:'tx.detection_inbound_anomaly_score=0',\\
    setvar:'tx.inbound_anomaly_score_pl1=0',\\
    setvar:'tx.inbound_anomaly_score_pl2=0',\\
    setvar:'tx.inbound_anomaly_score_pl3=0',\\
    setvar:'tx.inbound_anomaly_score_pl4=0'"

    SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:944011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.11.0-dev',skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA"

    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\\\d+$" \\
    "id:920160,\\
    phase:1,\\
    block,\\
    t:none,\\
    tag:'paranoia-level/2',\\
    severity:'CRITICAL',\\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
    """


@pytest.mark.parametrize("rule,expected_count", [
    (PL_CONSISTENCY_RULE_VALID, 0),
    (PL_CONSISTENCY_RULE_INVALID, 2),  # tag mismatch + invalid value
])
def test_check_pl_consistency(run_linter, rule, expected_count):
    """Test paranoia level consistency checking."""
    problems = run_linter(rule, rule_type="pl_consistency")
    assert len(problems) == expected_count, \
        f"Expected {expected_count} PL consistency problems, got {len(problems)}"


@pytest.mark.parametrize("rule,tags_list,expected_count", [
    ('SecRule REQUEST_URI "@rx index.php" "id:1,phase:1,deny,t:none,nolog,tag:OWASP_CRS"',
     ["PIZZA", "OWASP_CRS"], 0),
    ('SecRule REQUEST_URI "@rx index.php" "id:1,phase:1,deny,t:none,nolog,tag:PINEAPPLE"',
     ["OWASP_CRS", "PIZZA"], 1),
])
def test_check_tags(run_linter, rule, tags_list, expected_count):
    """Test approved tags checking."""
    problems = run_linter(rule, rule_type="approved_tags", tagslist=tags_list)
    assert len(problems) == expected_count


@pytest.mark.parametrize("rule,expected_count,description", [
    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:900100,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:OWASP_CRS,\\
    tag:OWASP_CRS/CHECK-TAG"''', 0, "has both OWASP_CRS tags"),

    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:900110,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:attack-xss"''', 2, "missing both OWASP_CRS tags"),

    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:911200,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:attack-xss,\\
    tag:OWASP_CRS"''', 1, "missing filename tag"),

    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:911200,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:attack-xss,\\
    tag:OWASP_CRS/CHECK-TAG"''', 1, "missing OWASP_CRS tag"),
])
def test_check_crs_tag(run_linter, rule, expected_count, description):
    """Test CRS tag checking with filename context."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        # Use specific filename for CRS tag checking
        linter = Linter(parsed, filename="REQUEST-900-CHECK-TAG.conf")
        problems = list(linter.run_checks())

        crs_tag_problems = [p for p in problems if p.rule == "crs_tag"]
        assert len(crs_tag_problems) == expected_count, \
            f"{description}: expected {expected_count} problems, got {len(crs_tag_problems)}"
    finally:
        os.unlink(temp_file)


@pytest.mark.parametrize("rule,expected_count", [
    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:2,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:OWASP_CRS,\\
    ver:'OWASP_CRS/4.10.0'"''', 0),

    ('''SecRule REQUEST_URI "@rx index.php" \\
    "id:2,\\
    phase:1,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:OWASP_CRS,\\
    ver:OWASP_CRS/1.0.0-dev"''', 1),
])
def test_check_ver_action(run_linter, crsversion, rule, expected_count):
    """Test version action checking."""
    problems = run_linter(rule, rule_type="version", crs_version=crsversion)
    assert len(problems) == expected_count


@pytest.mark.parametrize("rule,expected_count", [
    ('''SecRule ARGS "@rx attack" \\
    "id:2,\\
    phase:2,\\
    deny,\\
    capture,\\
    t:none,\\
    nolog,\\
    tag:OWASP_CRS,\\
    ver:'OWASP_CRS/4.7.0-dev',\\
    chain"
    SecRule TX:1 "@eq attack"''', 0),

    ('''SecRule ARGS "@rx attack" \\
    "id:3,\\
    phase:2,\\
    deny,\\
    t:none,\\
    nolog,\\
    tag:OWASP_CRS,\\
    ver:'OWASP_CRS/4.7.0-dev',\\
    chain"
    SecRule TX:0 "@eq attack"''', 1),
])
def test_check_capture_action(run_linter, rule, expected_count):
    """Test capture action checking."""
    problems = run_linter(rule, rule_type="capture")
    assert len(problems) == expected_count
