import sys

from crs_linter.cli import main


def test_cli(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crs-linter",
            "-v",
            "4.10.0",
            "-r",
            "examples/test1.conf",
            "-r",
            "examples/test?.conf",
            "-t",
            "./APPROVED_TAGS",
            "-T",
            "examples/test/regression/tests/",
            "-E",
            "./TESTS_EXCLUSIONS",
             "-d",
             ".",
            "-d",
            ".",
        ],
    )

    ret = main()

    assert ret == 0
