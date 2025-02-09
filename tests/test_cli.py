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
            "../examples/test1.conf",
            "-r",
            "../examples/test?.conf",
            "-t",
            "./APPROVED_TAGS",
            "-d",
            ".",
        ],
    )

    ret = main()

    assert ret == 0
