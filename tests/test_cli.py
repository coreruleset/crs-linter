import sys

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
