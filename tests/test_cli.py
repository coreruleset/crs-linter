import sys

from crs_linter.cli import main


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
