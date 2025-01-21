from crs_linter.cli import main


def test_cli():
    ret = main(["-v", "4.10.0", "-r", "../examples/*.conf", "-t", "./APPROVED_TAGS", "-d", "."])

    assert ret == 0
