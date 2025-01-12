from crs_linter.linter import Check


def test_check(data, txvars):
    c = Check(data, txvars)
    c.check_ignore_case()

    assert len(c.caseerror) == 0
