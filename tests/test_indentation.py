import tempfile
import os
from pathlib import Path
from crs_linter.linter import Linter, parse_config


def test_check_indentation_proper_format():
    """Test that properly formatted CRS rules pass indentation check.

    This uses the CRS format with:
    - 4 spaces for indentation
    - Proper line continuation with backslash
    - Actions properly formatted on separate lines
    - No trailing newline (as per msc_pyparser formatter)
    """
    # Properly formatted CRS rule following CONTRIBUTING.md guidelines
    # Note: No leading spaces, no trailing newline
    properly_formatted = (
        'SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\\n'
        '    "id:920100,\\\n'
        '    phase:1,\\\n'
        '    block,\\\n'
        '    capture,\\\n'
        '    t:none,\\\n'
        '    t:lowercase,\\\n'
        '    msg:\'Bad User Agent\',\\\n'
        '    logdata:\'Matched Data: %{MATCHED_VAR}\',\\\n'
        '    tag:\'application-multi\',\\\n'
        '    tag:\'language-multi\',\\\n'
        '    tag:\'platform-multi\',\\\n'
        '    tag:\'attack-generic\',\\\n'
        '    tag:\'paranoia-level/1\',\\\n'
        '    tag:\'OWASP_CRS\',\\\n'
        '    tag:\'capec/1000/152/137\',\\\n'
        '    tag:\'PCI/6.5.10\',\\\n'
        '    ver:\'OWASP_CRS/4.10.0\',\\\n'
        '    severity:\'CRITICAL\',\\\n'
        '    setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\'"'
    )

    # Create a temporary file with properly formatted content
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(properly_formatted)
        temp_file = f.name

    try:
        # Parse the content
        p = parse_config(properly_formatted)
        assert p is not None

        # Run linter with the actual file
        c = Linter(p, filename=temp_file, file_content=properly_formatted)
        problems = list(c.run_checks())

        # Should have no indentation problems for properly formatted rules
        indentation_problems = [p for p in problems if p.rule == "indentation"]
        assert len(indentation_problems) == 0, f"Expected no indentation problems, but found: {indentation_problems}"
    finally:
        # Clean up temporary file
        os.unlink(temp_file)


def test_check_indentation_broken_format():
    """Test that improperly formatted rules are caught by indentation check.

    This test uses broken indentation with:
    - Incorrect spacing (2 spaces instead of 4)
    - Improper alignment
    """
    # Improperly formatted rule with wrong indentation (2 spaces instead of 4)
    # Note: No leading spaces in Python string
    broken_formatted = (
        'SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\\n'
        '  "id:920100,\\\n'
        '  phase:1,\\\n'
        '  block,\\\n'
        '  capture,\\\n'
        '  t:none,\\\n'
        '  t:lowercase,\\\n'
        '  msg:\'Bad User Agent\',\\\n'
        '  logdata:\'Matched Data: %{MATCHED_VAR}\',\\\n'
        '  tag:\'application-multi\',\\\n'
        '  tag:\'language-multi\',\\\n'
        '  tag:\'platform-multi\',\\\n'
        '  tag:\'attack-generic\',\\\n'
        '  tag:\'paranoia-level/1\',\\\n'
        '  tag:\'OWASP_CRS\',\\\n'
        '  tag:\'capec/1000/152/137\',\\\n'
        '  tag:\'PCI/6.5.10\',\\\n'
        '  ver:\'OWASP_CRS/4.10.0\',\\\n'
        '  severity:\'CRITICAL\',\\\n'
        '  setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\'"'
    )

    # Create a temporary file with broken formatting
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(broken_formatted)
        temp_file = f.name

    try:
        # Parse the content
        p = parse_config(broken_formatted)
        assert p is not None

        # Run linter with the actual file
        c = Linter(p, filename=temp_file, file_content=broken_formatted)
        problems = list(c.run_checks())

        # Should have indentation problems for improperly formatted rules
        indentation_problems = [p for p in problems if p.rule == "indentation"]
        assert len(indentation_problems) > 0, "Expected indentation problems for broken formatting"

        # Verify that the error message mentions indentation/formatting
        assert any("Indentation" in str(p.desc) for p in indentation_problems), \
            f"Expected indentation error message, got: {[p.desc for p in indentation_problems]}"
    finally:
        # Clean up temporary file
        os.unlink(temp_file)


def test_check_indentation_trailing_newline():
    """Test that rules with a trailing newline are accepted.

    The msc_pyparser formatter does not add a trailing newline,
    but most editors do. We normalize trailing newlines so that
    properly formatted files with trailing newlines pass the check.
    This matches the behavior of the official CRS files.
    """
    # Properly formatted with trailing newline (common in many editors)
    with_trailing_newline = (
        'SecRule REQUEST_URI "@beginswith /index.php" \\\n'
        '    "id:1,\\\n'
        '    phase:1,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    nolog"\n'  # <- This trailing newline is acceptable
    )

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(with_trailing_newline)
        temp_file = f.name

    try:
        # Parse the content
        p = parse_config(with_trailing_newline)
        assert p is not None

        # Run linter with the actual file
        c = Linter(p, filename=temp_file, file_content=with_trailing_newline)
        problems = list(c.run_checks())

        # Should NOT have indentation problems - trailing newlines are normalized
        indentation_problems = [p for p in problems if p.rule == "indentation"]
        assert len(indentation_problems) == 0, f"Expected no indentation problems for trailing newline, but found: {indentation_problems}"
    finally:
        # Clean up temporary file
        os.unlink(temp_file)


def test_check_indentation_mixed_spacing():
    """Test that rules with mixed tabs and spaces are caught."""
    # Using tabs instead of spaces in some lines
    mixed_spacing = (
        'SecRule REQUEST_HEADERS:User-Agent "@rx (?:my|bad|test)" \\\n'
        '\t"id:920100,\\\n'  # Tab instead of 4 spaces
        '    phase:1,\\\n'
        '\tblock,\\\n'  # Tab instead of 4 spaces
        '    tag:\'OWASP_CRS\',\\\n'
        '    ver:\'OWASP_CRS/4.10.0\'"'
    )

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(mixed_spacing)
        temp_file = f.name

    try:
        # Parse the content
        p = parse_config(mixed_spacing)
        assert p is not None

        # Run linter with the actual file
        c = Linter(p, filename=temp_file, file_content=mixed_spacing)
        problems = list(c.run_checks())

        # Should have indentation problems for mixed tabs/spaces
        indentation_problems = [p for p in problems if p.rule == "indentation"]
        assert len(indentation_problems) > 0, "Expected indentation problems for mixed tabs/spaces"
    finally:
        # Clean up temporary file
        os.unlink(temp_file)
