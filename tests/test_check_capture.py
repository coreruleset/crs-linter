import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_capture_check_target_without_capture_fails():
    """Test that using TX.N as target without capture is caught (original functionality)."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    nolog,\\\n'
        '    chain"\n'
        '    SecRule TX:0 "@eq attack"'  # Uses TX:0 without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for TX:0 target without capture action"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_capture_check_msg_without_capture_fails():
    """Test that using %{TX.N} in msg without capture is caught."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    msg:\'Attack detected: %{TX.1}\'"'  # Uses %{TX.1} without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX.1} in msg without capture action"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_capture_check_logdata_without_capture_fails():
    """Test that using %{TX.N} in logdata without capture is caught."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1003,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    logdata:\'Matched data: %{TX.0}\'"'  # Uses %{TX.0} without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX.0} in logdata without capture action"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_capture_check_setvar_without_capture_fails():
    """Test that using %{TX.N} in setvar without capture is caught."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1004,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        "    setvar:'tx.foo=%{TX.1}'\""  # Uses %{TX.1} without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX.1} in setvar without capture action"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_capture_check_tag_without_capture_fails():
    """Test that using %{TX.N} in tag without capture is caught."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1005,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        '    tag:\'attack-%{TX.0}\'"'  # Uses %{TX.0} without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX.0} in tag without capture action"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_capture_check_with_capture_passes():
    """Test that using TX.N with capture action passes."""
    valid_rule = (
        'SecRule ARGS "@rx (attack)" \\\n'
        '    "id:2001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    msg:\'Attack detected: %{TX.1}\',\\\n'
        '    logdata:\'Pattern: %{TX.0}\'"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) == 0, \
            f"Expected no capture errors with capture action, but found: {capture_problems}"
    finally:
        os.unlink(temp_file)


def test_capture_check_chained_with_capture_passes():
    """Test that chained rules with capture action pass."""
    valid_rule = (
        'SecRule ARGS "@rx (attack)" \\\n'
        '    "id:2002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    msg:\'Attack detected: %{TX.1}\',\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq attack"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) == 0, \
            f"Expected no capture errors with capture in chained rule, but found: {capture_problems}"
    finally:
        os.unlink(temp_file)


def test_capture_check_multiple_tx_references():
    """Test that multiple TX.N references without capture are all caught."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1006,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    msg:\'Attack: %{TX.1}\',\\\n'
        '    logdata:\'Data: %{TX.0}\'"'  # Multiple TX.N references
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for multiple TX.N references without capture"
    finally:
        os.unlink(temp_file)


def test_capture_check_case_insensitive():
    """Test that TX.N detection is case-insensitive."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1007,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    msg:\'Attack: %{tx.1}\'"'  # Lowercase tx
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for lowercase %{tx.1} without capture"
    finally:
        os.unlink(temp_file)


def test_capture_check_colon_syntax():
    """Test that TX:N syntax (with colon) is detected."""
    invalid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:1008,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    msg:\'Attack: %{TX:1}\'"'  # TX:1 with colon
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX:1} (colon syntax) without capture"
    finally:
        os.unlink(temp_file)


def test_capture_check_no_false_positive_on_other_tx_vars():
    """Test that non-captured TX variables (like TX:foo) don't trigger false positives."""
    valid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:2003,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        '    msg:\'Attack: %{TX.custom_var}\',\\\n'
        '    setvar:tx.custom_var=1"'  # TX.custom_var is not a captured variable
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        # Should not report capture errors for non-numeric TX variables
        assert len(capture_problems) == 0, \
            f"Should not flag non-captured TX variables, but found: {capture_problems}"
    finally:
        os.unlink(temp_file)


def test_capture_check_operator_argument():
    """Test that TX.N in operator arguments without capture is caught."""
    invalid_rule = (
        'SecRule ARGS "@rx %{TX.1}" \\\n'  # TX.1 in operator argument
        '    "id:1009,\\\n'
        '    phase:2,\\\n'
        '    deny"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for %{TX.1} in operator argument without capture"
    finally:
        os.unlink(temp_file)


def test_capture_check_first_rule_in_chain_allowed():
    """Test that TX.N in first rule of chain without capture is allowed."""
    valid_rule = (
        'SecRule TX:1 "@eq foo" \\\n'  # TX:1 in first rule - allowed
        '    "id:2004,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        '    chain"\n'
        '    SecRule ARGS "@rx bar"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        # First rule in chain is allowed to use TX:N without capture
        assert len(capture_problems) == 0, \
            f"First rule in chain should be allowed to use TX:N, but found: {capture_problems}"
    finally:
        os.unlink(temp_file)


def test_capture_check_tx_as_target_and_expansion_without_capture_fails():
    """Test that using TX.N both as target and in expansion without capture is caught.
    
    This test covers the scenario where TX.N appears as both a target variable
    and in an expansion (e.g., in msg or logdata) within the same rule.
    This would catch the bug where use_captured_var_in_expansion is not set
    correctly when use_captured_var is already True.
    """
    invalid_rule = (
        'SecRule TX:1 "@eq foo" \\\n'  # TX:1 as target
        '    "id:3001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        "    msg:'Value: %{TX.1}'\""  # TX.1 in expansion without capture
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        capture_problems = [p for p in problems if p.rule == "capture"]
        assert len(capture_problems) > 0, \
            "Expected capture error for TX.1 used as both target and in msg expansion without capture"
        assert "TX.N" in capture_problems[0].desc
    finally:
        os.unlink(temp_file)
