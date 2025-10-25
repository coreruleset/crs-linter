from crs_linter.linter import Linter, parse_config


def test_parser():
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    p = parse_config(t)

    assert p is not None


def test_check_ignore_proper_case():
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for proper case
    ignore_case_problems = [p for p in problems if p.rule == "ignore_case"]
    assert len(ignore_case_problems) == 0


def test_check_ignore_case_fail_invalid_action_case():
    """Two actions are in the wrong case."""
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,LOG,NoLOg,status:403"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 2 problems for wrong case
    ignore_case_problems = [p for p in problems if p.rule == "ignore_case"]
    assert len(ignore_case_problems) == 2


def test_check_action_order():
    """Test that the actions are in the correct order."""
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,nolog"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for correct order
    ordered_actions_problems = [p for p in problems if p.rule == "ordered_actions"]
    assert len(ordered_actions_problems) == 0


def test_check_action_fail_wrong_order():
    """Test if the action is in the wrong order. status should go before log"""
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 1 problem for wrong order
    ordered_actions_problems = [p for p in problems if p.rule == "ordered_actions"]
    assert len(ordered_actions_problems) == 1


def test_check_ctl_auditctl_log_parts():
    """Test that there is no ctl:auditLogParts action in any rules"""
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for valid ctl
    ctl_audit_log_problems = [p for p in problems if p.rule == "ctl_audit_log"]
    assert len(ctl_audit_log_problems) == 0


def test_check_wrong_ctl_audit_log_parts():
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Pizza" "id:1,phase:1,log,ctl:auditLogParts=+E"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 1 problem for forbidden ctl:auditLogParts
    ctl_audit_log_problems = [p for p in problems if p.rule == "ctl_audit_log"]
    assert len(ctl_audit_log_problems) == 1


def test_check_tx_variable():
    """Test that variables are defined in the transaction"""
    t = """SecRule &TX:blocking_paranoia_level "@eq 0" \
    "id:901120,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/4.0.0-rc1',\
    setvar:'tx.blocking_paranoia_level=1'"

SecRule &TX:detection_paranoia_level "@eq 0" \
    "id:901125,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/4.0.0-rc1',\
    setvar:'tx.detection_paranoia_level=%{TX.blocking_paranoia_level}'"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for properly defined variables
    variables_usage_problems = [p for p in problems if p.rule == "variables_usage"]
    assert len(variables_usage_problems) == 0


def test_check_tx_variable_fail_nonexisting():
    t = """SecRule TX:foo "@rx bar" \
    "id:1001,\
    phase:1,\
    pass,\
    nolog"

SecRule ARGS "@rx ^.*$" \
    "id:1002,\
    phase:1,\
    pass,\
    nolog,\
    setvar:tx.bar=1"
        """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 1 problem for undefined variable
    variables_usage_problems = [p for p in problems if p.rule == "variables_usage"]
    assert len(variables_usage_problems) == 1


def test_check_pl_consistency():
    t = """
    SecAction \
    "id:901200,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.11.0-dev',\
    setvar:'tx.blocking_inbound_anomaly_score=0',\
    setvar:'tx.detection_inbound_anomaly_score=0',\
    setvar:'tx.inbound_anomaly_score_pl1=0',\
    setvar:'tx.inbound_anomaly_score_pl2=0',\
    setvar:'tx.inbound_anomaly_score_pl3=0',\
    setvar:'tx.inbound_anomaly_score_pl4=0'"
    
    SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:944011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.11.0-dev',skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA"
    
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \
    "id:920160,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for consistent PL
    pl_consistency_problems = [p for p in problems if p.rule == "pl_consistency"]
    assert len(pl_consistency_problems) == 0


def test_check_pl_consistency_fail():
    t = """
    SecAction \
    "id:901200,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.11.0-dev',\
    setvar:'tx.blocking_inbound_anomaly_score=0',\
    setvar:'tx.detection_inbound_anomaly_score=0',\
    setvar:'tx.inbound_anomaly_score_pl1=0',\
    setvar:'tx.inbound_anomaly_score_pl2=0',\
    setvar:'tx.inbound_anomaly_score_pl3=0',\
    setvar:'tx.inbound_anomaly_score_pl4=0'"

    SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:944011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.11.0-dev',skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA"

    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \
    "id:920160,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/2',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 2 problems for inconsistent PL (tag mismatch and invalid value)
    pl_consistency_problems = [p for p in problems if p.rule == "pl_consistency"]
    assert len(pl_consistency_problems) == 2


def test_check_tags():
    t = """
    SecRule REQUEST_URI "@rx index.php" \
        "id:1,\
        phase:1,\
        deny,\
        t:none,\
        nolog,\
        tag:OWASP_CRS"
        """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks(tagslist=["PIZZA", "OWASP_CRS"]))

    # Should have no problems for approved tags
    approved_tags_problems = [p for p in problems if p.rule == "approved_tags"]
    assert len(approved_tags_problems) == 0


def test_check_tags_fail():
    t = """
    SecRule REQUEST_URI "@rx index.php" \
        "id:1,\
        phase:1,\
        deny,\
        t:none,\
        nolog,\
        tag:PINEAPPLE"
        """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks(tagslist=["OWASP_CRS", "PIZZA"]))

    # Should have 1 problem for unapproved tag
    approved_tags_problems = [p for p in problems if p.rule == "approved_tags"]
    assert len(approved_tags_problems) == 1


def test_check_lowercase_ignorecase():
    t = 'SecRule REQUEST_HEADERS:User-Agent "@rx ^Mozilla" "id:1,phase:1,log,status:403"'
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for proper case
    ignore_case_problems = [p for p in problems if p.rule == "ignore_case"]
    assert len(ignore_case_problems) == 0


def test_check_crs_tag():
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    tag:OWASP_CRS/CHECK-TAG"
    """
    p = parse_config(t)
    c = Linter(p, filename = "REQUEST-900-CHECK-TAG.conf")
    print(c.filename)
    problems = list(c.run_checks())

    # Should have no problems for rules with OWASP_CRS tag
    crs_tag_problems = [p for p in problems if p.rule == "crs_tag"]
    assert len(crs_tag_problems) == 0


def test_check_crs_tag_fail():
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss"
    """
    p = parse_config(t)
    c = Linter(p, filename = "REQUEST-900-CHECK-TAG.conf")
    problems = list(c.run_checks())

    # Should have 1 problem for rule without OWASP_CRS tag
    crs_tag_problems = [p for p in problems if p.rule == "crs_tag"]
    assert len(crs_tag_problems) == 1

def test_check_crs_tag_fail2():
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:911200,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss,\
    tag:OWASP_CRS"
    """
    p = parse_config(t)
    c = Linter(p, filename = "REQUEST-900-CHECK-TAG.conf")
    problems = list(c.run_checks())

    # Should have no problems for rule with OWASP_CRS tag
    crs_tag_problems = [p for p in problems if p.rule == "crs_tag"]
    assert len(crs_tag_problems) == 0

def test_check_crs_tag_fail3():
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:911200,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss,\
    tag:OWASP_CRS/CHECK-TAG"
    """
    p = parse_config(t)
    c = Linter(p, filename = "REQUEST-900-CHECK-TAG.conf")
    problems = list(c.run_checks())

    # Should have 1 problem for rule without OWASP_CRS tag
    crs_tag_problems = [p for p in problems if p.rule == "crs_tag"]
    assert len(crs_tag_problems) == 1

def test_check_ver_action(crsversion):
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:2,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.10.0'"    
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks(crs_version=crsversion))

    # Should have no problems for correct version
    version_problems = [p for p in problems if p.rule == "version"]
    assert len(version_problems) == 0


def test_check_ver_action_fail(crsversion):
    t = """
SecRule REQUEST_URI "@rx index.php" \
    "id:2,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:OWASP_CRS/1.0.0-dev"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks(crs_version=crsversion))

    # Should have 1 problem for incorrect version
    version_problems = [p for p in problems if p.rule == "version"]
    assert len(version_problems) == 1


def test_check_capture_action():
    t = """
SecRule ARGS "@rx attack" \
    "id:2,\
    phase:2,\
    deny,\
    capture,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.7.0-dev',\
    chain"
    SecRule TX:1 "@eq attack"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have no problems for proper capture usage
    capture_problems = [p for p in problems if p.rule == "capture"]
    assert len(capture_problems) == 0


def test_check_capture_action_fail():
    t = """
SecRule ARGS "@rx attack" \
    "id:3,\
    phase:2,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.7.0-dev',\
    chain"
    SecRule TX:0 "@eq attack"
    """
    p = parse_config(t)
    c = Linter(p)
    problems = list(c.run_checks())

    # Should have 1 problem for missing capture action
    capture_problems = [p for p in problems if p.rule == "capture"]
    assert len(capture_problems) == 1
