from crs_linter.linter import Check

def test_check(data, txvars):
    c = Check(data, txvars)
    assert c.check_ignore_case() == True
