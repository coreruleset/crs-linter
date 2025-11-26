"""Tests for the duplicated IDs checker."""

import pytest


def test_no_duplicate_ids():
    """Test that rules with unique IDs pass the check."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecRule ARGS "@rx attack" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS_NAMES "@rx malicious" \\
    "id:1002,\\
    phase:2,\\
    block,\\
    t:none"

SecRule REQUEST_URI "@rx admin" \\
    "id:1003,\\
    phase:1,\\
    deny,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}  # Track IDs to detect duplicates
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 0, \
            "Rules with unique IDs should not trigger duplicate errors"
    finally:
        os.unlink(temp_file)


def test_duplicate_ids_in_same_file():
    """Test that duplicate IDs in the same file are detected."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecRule ARGS "@rx attack" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS_NAMES "@rx malicious" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 1, \
            "Duplicate ID should be detected"
        assert "1001" in duplicated_problems[0].desc, \
            "Error message should mention the duplicate ID"
    finally:
        os.unlink(temp_file)


def test_multiple_duplicate_ids():
    """Test detection of multiple sets of duplicate IDs."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecRule ARGS "@rx attack" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack2" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack3" \\
    "id:1002,\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack4" \\
    "id:1002,\\
    phase:2,\\
    block,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 2, \
            "Should detect both duplicate IDs"
    finally:
        os.unlink(temp_file)


def test_duplicate_ids_across_files():
    """Test that duplicate IDs across different files are detected."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule1 = '''SecRule ARGS "@rx attack" \\
    "id:2001,\\
    phase:2,\\
    block,\\
    t:none"'''

    rule2 = '''SecRule REQUEST_URI "@rx admin" \\
    "id:2001,\\
    phase:1,\\
    deny,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f1:
        f1.write(rule1)
        temp_file1 = f1.name

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f2:
        f2.write(rule2)
        temp_file2 = f2.name

    try:
        ids = {}  # Shared IDs dict across both files

        # Process first file
        parsed1 = parse_config(rule1)
        linter1 = Linter(parsed1, filename=temp_file1, file_content=rule1, ids=ids)
        problems1 = list(linter1.run_checks())
        duplicated_problems1 = [p for p in problems1 if p.rule == "duplicated"]

        # First file should have no duplicates
        assert len(duplicated_problems1) == 0

        # Process second file with same ids dict
        parsed2 = parse_config(rule2)
        linter2 = Linter(parsed2, filename=temp_file2, file_content=rule2, ids=ids)
        problems2 = list(linter2.run_checks())
        duplicated_problems2 = [p for p in problems2 if p.rule == "duplicated"]

        # Second file should detect duplicate from first file
        assert len(duplicated_problems2) == 1, \
            "Duplicate ID across files should be detected"
        assert "2001" in duplicated_problems2[0].desc
        assert temp_file1 in duplicated_problems2[0].desc, \
            "Error should reference the first file where ID was defined"
    finally:
        os.unlink(temp_file1)
        os.unlink(temp_file2)


def test_rules_without_ids_are_skipped():
    """Test that rules without IDs don't cause issues."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecRule ARGS "@rx attack" \\
    "phase:2,\\
    block,\\
    t:none"

SecRule ARGS_NAMES "@rx malicious" \\
    "id:1001,\\
    phase:2,\\
    block,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 0, \
            "Rules without IDs should be skipped"
    finally:
        os.unlink(temp_file)


def test_secaction_duplicate_detection():
    """Test that SecAction directives are checked for duplicate IDs."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecAction \\
    "id:3001,\\
    phase:1,\\
    pass,\\
    nolog,\\
    setvar:tx.test=1"

SecRule ARGS "@rx foo" \\
    "id:3001,\\
    phase:2,\\
    block,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 1, \
            "Duplicate ID between SecAction and SecRule should be detected"
    finally:
        os.unlink(temp_file)


def test_chained_rules_with_unique_ids():
    """Test that chained rules with unique IDs don't trigger duplicates."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = '''SecRule ARGS "@rx attack" \\
    "id:4001,\\
    phase:2,\\
    block,\\
    t:none,\\
    chain"
    SecRule ARGS "@rx malicious" \\
    "t:lowercase"

SecRule REQUEST_URI "@rx admin" \\
    "id:4002,\\
    phase:1,\\
    deny,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]
        assert len(duplicated_problems) == 0, \
            "Chained rules should not trigger false duplicates"
    finally:
        os.unlink(temp_file)


@pytest.mark.parametrize("id1,id2,should_duplicate", [
    (1001, 1002, False),  # Different IDs
    (1001, 1001, True),   # Same IDs
    (942100, 943100, False),  # Different IDs from different rule ranges
    (920100, 920100, True),   # Same ID in same range
])
def test_duplicate_detection_parametrized(id1, id2, should_duplicate):
    """Parametrized test for duplicate ID detection."""
    from crs_linter.linter import Linter, parse_config
    import tempfile
    import os

    rule = f'''SecRule ARGS "@rx attack1" \\
    "id:{id1},\\
    phase:2,\\
    block,\\
    t:none"

SecRule ARGS "@rx attack2" \\
    "id:{id2},\\
    phase:2,\\
    block,\\
    t:none"'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        ids = {}
        linter = Linter(parsed, filename=temp_file, file_content=rule, ids=ids)
        problems = list(linter.run_checks())

        duplicated_problems = [p for p in problems if p.rule == "duplicated"]

        if should_duplicate:
            assert len(duplicated_problems) == 1, \
                f"IDs {id1} and {id2} should be detected as duplicates"
        else:
            assert len(duplicated_problems) == 0, \
                f"IDs {id1} and {id2} should not be detected as duplicates"
    finally:
        os.unlink(temp_file)
