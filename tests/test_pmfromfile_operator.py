import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_pmFromFile_single_file():
    """Test that pmFromFile with a single file is parsed and linted correctly."""
    rule = (
        'SecRule ARGS "@pmFromFile data/unix-shell.data" \\\n'
        '    "id:932100,\\\n'
        '    phase:2,\\\n'
        '    block,\\\n'
        '    t:none,\\\n'
        '    msg:\'Unix Shell Command Injection\',\\\n'
        '    tag:\'OWASP_CRS\',\\\n'
        '    ver:\'OWASP_CRS/4.0.0\'"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        assert parsed is not None, "Failed to parse rule with single pmFromFile"

        # Verify the operator was parsed correctly
        assert parsed[0]["operator"] == "@pmFromFile"
        assert parsed[0]["operator_argument"] == "data/unix-shell.data"

        # Run linter - should not error
        linter = Linter(parsed, filename=temp_file, file_content=rule)
        problems = list(linter.run_checks())

        # Should not have any parsing or operator-related errors
        # (may have other errors like missing capture, wrong tags, etc.)
        assert parsed is not None, "Linter should handle single pmFromFile without errors"
    finally:
        os.unlink(temp_file)


def test_pmFromFile_multiple_files():
    """Test that pmFromFile with multiple files is parsed and linted correctly.

    This test addresses GitHub issue #44: crs-linter doesn't support passing
    multiple files to pmFromFile.

    According to ModSecurity documentation, @pmFromFile can accept multiple
    space-separated file paths, e.g., "@pmFromFile file1.data file2.data file3.data"
    """
    rule = (
        'SecRule ARGS "@pmFromFile data/unix-shell-builtins.data data/unix-shell-aliases.data" \\\n'
        '    "id:932101,\\\n'
        '    phase:2,\\\n'
        '    block,\\\n'
        '    t:none,\\\n'
        '    msg:\'Unix Shell Command Injection\',\\\n'
        '    tag:\'OWASP_CRS\',\\\n'
        '    ver:\'OWASP_CRS/4.0.0\'"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        assert parsed is not None, "Failed to parse rule with multiple pmFromFile files"

        # Verify the operator was parsed correctly
        assert parsed[0]["operator"] == "@pmFromFile"

        # The operator_argument should contain both files (space-separated)
        operator_arg = parsed[0]["operator_argument"]
        assert "unix-shell-builtins.data" in operator_arg, \
            "First file should be in operator argument"
        assert "unix-shell-aliases.data" in operator_arg, \
            "Second file should be in operator argument"

        # Run linter - should not error on multiple files
        linter = Linter(parsed, filename=temp_file, file_content=rule)
        problems = list(linter.run_checks())

        # Should not have any parsing or operator-related errors
        # The linter should handle multiple space-separated files gracefully
        assert parsed is not None, "Linter should handle multiple pmFromFile files without errors"
    finally:
        os.unlink(temp_file)


def test_pmFromFile_three_files():
    """Test that pmFromFile with three files is parsed and linted correctly."""
    rule = (
        'SecRule ARGS "@pmFromFile file1.data file2.data file3.data" \\\n'
        '    "id:932102,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        '    t:none,\\\n'
        '    nolog"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        assert parsed is not None, "Failed to parse rule with three pmFromFile files"

        # Verify all three files are in the operator argument
        operator_arg = parsed[0]["operator_argument"]
        assert "file1.data" in operator_arg
        assert "file2.data" in operator_arg
        assert "file3.data" in operator_arg

        # Run linter - should not error
        linter = Linter(parsed, filename=temp_file, file_content=rule)
        problems = list(linter.run_checks())

        assert parsed is not None, "Linter should handle three pmFromFile files without errors"
    finally:
        os.unlink(temp_file)


def test_ipMatchFromFile_multiple_files():
    """Test that ipMatchFromFile with multiple files is parsed correctly.

    Similar to pmFromFile, ipMatchFromFile should also support multiple files.
    """
    rule = (
        'SecRule REMOTE_ADDR "@ipMatchFromFile data/blocklist1.txt data/blocklist2.txt" \\\n'
        '    "id:910100,\\\n'
        '    phase:1,\\\n'
        '    deny,\\\n'
        '    status:403,\\\n'
        '    msg:\'IP address blocked\'"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        assert parsed is not None, "Failed to parse rule with multiple ipMatchFromFile files"

        # Verify the operator was parsed correctly
        assert parsed[0]["operator"] == "@ipMatchFromFile"

        operator_arg = parsed[0]["operator_argument"]
        assert "blocklist1.txt" in operator_arg
        assert "blocklist2.txt" in operator_arg

        # Run linter - should not error
        linter = Linter(parsed, filename=temp_file, file_content=rule)
        problems = list(linter.run_checks())

        assert parsed is not None, "Linter should handle multiple ipMatchFromFile files without errors"
    finally:
        os.unlink(temp_file)


def test_pmFromFile_with_paths():
    """Test that pmFromFile with full paths works correctly."""
    rule = (
        'SecRule ARGS "@pmFromFile /etc/crs/data/file1.data /etc/crs/data/file2.data" \\\n'
        '    "id:932103,\\\n'
        '    phase:2,\\\n'
        '    pass,\\\n'
        '    t:none"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(rule)
        temp_file = f.name

    try:
        parsed = parse_config(rule)
        assert parsed is not None, "Failed to parse rule with full path pmFromFile files"

        # Verify paths are preserved
        operator_arg = parsed[0]["operator_argument"]
        assert "/etc/crs/data/file1.data" in operator_arg
        assert "/etc/crs/data/file2.data" in operator_arg

        # Run linter
        linter = Linter(parsed, filename=temp_file, file_content=rule)
        problems = list(linter.run_checks())

        assert parsed is not None, "Linter should handle pmFromFile with full paths"
    finally:
        os.unlink(temp_file)
