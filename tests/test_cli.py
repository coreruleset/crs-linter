from crs_linter.cli import main


def test_cli(mocker):
    mocker.patch(
        "sys.argv",
        ["-v", "4.10.0", "-r", "../examples/*.conf", "-t", "./APPROVED_TAGS", "-d", "."]
    )
    ret = main()

    assert ret == 0
