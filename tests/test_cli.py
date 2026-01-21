import sys
import pytest

from crs_linter.cli import *
from pathlib import Path
from dulwich.errors import NotGitRepository


def test_cli(monkeypatch, tmp_path):
    approved_tags = tmp_path / "APPROVED_TAGS"
    test_exclusions = tmp_path / "TEST_EXCLUSIONS"
    approved_tags.write_text("")
    test_exclusions.write_text("")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crs-linter",
            "-v",
            "4.10.0",
            "-r",
            "../examples/test1.conf",
            "-r",
            "../examples/test?.conf",
            "-t",
            str(approved_tags),
            "-T",
            "examples/test/regression/tests/",
            "-E",
            str(test_exclusions),
            "-d",
            ".",
        ],
    )

    ret = main()

    assert ret == 0


def test_cli_error_exit_code(monkeypatch, tmp_path):
    """Test that CLI returns non-zero exit code on error"""
    test_exclusions = tmp_path / "TEST_EXCLUSIONS"
    test_exclusions.write_text("")

    # Use a non-existent tags list file to trigger an error
    non_existent_tags = tmp_path / "NON_EXISTENT_TAGS"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crs-linter",
            "-v",
            "4.10.0",
            "-r",
            "../examples/test1.conf",
            "-t",
            str(non_existent_tags),  # This file doesn't exist
            "-T",
            "examples/test/regression/tests/",
            "-E",
            str(test_exclusions),
            "-d",
            ".",
        ],
    )

    # The CLI calls sys.exit(1) on error, which raises SystemExit
    try:
        ret = main()
        # If we get here without exception, check the return code
        assert ret != 0
    except SystemExit as e:
        # Verify that the exit code is non-zero
        assert e.code != 0


def test_generate_version_string_from_commit_message():
    version_string = generate_version_string(
        Path("/tmp"), None, "chore: release v1.2.3"
    )
    assert version_string is not None
    assert version_string == "OWASP_CRS/1.2.3"


def test_generate_version_string_ignoring_post_commit_message():
    # Post release commit message should be ignored
    version_string = generate_version_string(
        Path("/tmp"), "release/v2.3.4", "chore: post release v1.2.3"
    )
    assert version_string is not None
    assert version_string == "OWASP_CRS/2.3.4"


def test_generate_version_string_from_branch_name():
    version_string = generate_version_string(Path("/tmp"), "release/v1.2.3", None)
    assert version_string is not None
    assert version_string == "OWASP_CRS/1.2.3"


def test_generate_version_string_ignoring_post_branch_name():
    caught = False
    try:
        generate_version_string(Path("/tmp"), "post-release/v1.2.3", None)
    except NotGitRepository as ex:
        caught = True
    assert caught


def test_parsing_failure_exits_with_error_code_when_fail_fast(monkeypatch, tmp_path):
    """Test that parsing failures exit with code 1 when --fail-fast is used"""
    # Create a malformed rule file that will fail parsing
    invalid_rule = tmp_path / "invalid.conf"
    invalid_rule.write_text("SecRule INVALID SYNTAX @@@@ THIS WILL NOT PARSE")

    # Create required config files
    approved_tags = tmp_path / "APPROVED_TAGS"
    test_exclusions = tmp_path / "TEST_EXCLUSIONS"
    approved_tags.write_text("")
    test_exclusions.write_text("")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crs-linter",
            "-v",
            "4.10.0",
            "-r",
            str(invalid_rule),
            "-t",
            str(approved_tags),
            "-E",
            str(test_exclusions),
            "--fail-fast",
        ],
    )

    # The program should exit with code 1 when parsing fails with --fail-fast
    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1


def test_parsing_failure_continues_without_fail_fast(monkeypatch, tmp_path):
    """Test that parsing failures continue without --fail-fast (default behavior)"""
    # Create a malformed rule file that will fail parsing
    invalid_rule = tmp_path / "invalid.conf"
    invalid_rule.write_text("SecRule INVALID SYNTAX @@@@ THIS WILL NOT PARSE")

    # Create a valid rule file
    valid_rule = tmp_path / "valid.conf"
    valid_rule.write_text("")

    # Create required config files
    approved_tags = tmp_path / "APPROVED_TAGS"
    test_exclusions = tmp_path / "TEST_EXCLUSIONS"
    approved_tags.write_text("")
    test_exclusions.write_text("")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crs-linter",
            "-v",
            "4.10.0",
            "-r",
            str(invalid_rule),
            "-r",
            str(valid_rule),
            "-t",
            str(approved_tags),
            "-E",
            str(test_exclusions),
        ],
    )

    # The program should continue and return 0 (since there are no linting errors in the valid file)
    # Note: The parsing error will be logged but won't cause an exit
    ret = main()

    # Should return 0 because the valid file has no linting issues
    assert ret == 0
