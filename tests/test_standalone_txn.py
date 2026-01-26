import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_standalone_rule_with_txn_fails():
    """Test that standalone rule using TX.N as target is caught."""
    invalid_rule = (
        'SecRule TX:4 "@eq 1" \\\n'
        '    "id:3001,\\\n'
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

        txn_problems = [p for p in problems if p.rule == "standalonetxn"]
        assert len(txn_problems) > 0, \
            "Expected error for standalone rule using TX:4"
        assert "3001" in txn_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_chained_rule_with_txn_passes():
    """Test that chained rule using TX.N as target is allowed."""
    valid_rule = (
        'SecRule ARGS "@rx (ab|cd)?(ef)" \\\n'
        '    "id:3002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq ef" \\\n'
        '        "t:none"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        txn_problems = [p for p in problems if p.rule == "standalonetxn"]
        assert len(txn_problems) == 0, \
            "Chained rule using TX:1 should be allowed"
    finally:
        os.unlink(temp_file)


def test_standalone_rule_without_txn_passes():
    """Test that standalone rule NOT using TX.N is allowed."""
    valid_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:3003,\\\n'
        '    phase:2,\\\n'
        '    deny"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        txn_problems = [p for p in problems if p.rule == "standalonetxn"]
        assert len(txn_problems) == 0, \
            "Standalone rule without TX.N should be allowed"
    finally:
        os.unlink(temp_file)


def test_multiple_standalone_rules_with_txn_detected():
    """Test that multiple standalone rules using TX.N are all caught."""
    invalid_rules = (
        'SecRule TX:0 "@eq 1" \\\n'
        '    "id:3004,\\\n'
        '    phase:2,\\\n'
        '    deny"\n'
        '\n'
        'SecRule TX:5 "@rx foo" \\\n'
        '    "id:3005,\\\n'
        '    phase:2,\\\n'
        '    deny"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rules)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rules)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rules)
        problems = list(linter.run_checks())

        txn_problems = [p for p in problems if p.rule == "standalonetxn"]
        assert len(txn_problems) == 2, \
            "Expected errors for both standalone rules using TX.N"
    finally:
        os.unlink(temp_file)


def test_chain_end_followed_by_standalone_txn_fails():
    """Test that standalone rule after chain end is caught."""
    invalid_rules = (
        'SecRule ARGS "@rx (test)" \\\n'
        '    "id:3006,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq test"\n'  # This is chained, OK
        '\n'
        'SecRule TX:2 "@eq foo" \\\n'  # This is standalone after chain, FAIL
        '    "id:3007,\\\n'
        '    phase:2,\\\n'
        '    deny"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rules)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rules)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=invalid_rules)
        problems = list(linter.run_checks())

        txn_problems = [p for p in problems if p.rule == "standalonetxn"]
        # Should catch the second standalone rule (3007) but not the chained one
        assert len(txn_problems) == 1, \
            "Expected error only for standalone rule 3007"
        assert "3007" in txn_problems[0].desc
    finally:
        os.unlink(temp_file)
