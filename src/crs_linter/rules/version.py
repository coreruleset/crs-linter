from crs_linter.lint_problem import LintProblem

def check(data, version):
    """
    check that every rule has a `ver` action
    """
    chained = False
    ruleid = 0
    has_ver = False
    ver_is_ok = False
    crsversion = version
    ruleversion = ""
    for d in data:
        if "actions" in d:
            chainlevel = 0

            if not chained:
                ruleid = 0
                has_ver = False
                ver_is_ok = False
                chainlevel = 0
            else:
                chained = False
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
                if a["act_name"] == "chain":
                    chained = True
                    chainlevel += 1
                if a["act_name"] == "ver":
                    if chainlevel == 0:
                        has_ver = True
                        if a["act_arg"] == version:
                            ver_is_ok = True
                        else:
                            ruleversion = a["act_arg"]
            if ruleid > 0 and chainlevel == 0:
                if not has_ver:
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule does not have 'ver' action; rule id: {ruleid}",
                        rule="version",
                    )
                else:
                    if not ver_is_ok:
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"rule's 'ver' action has incorrect value; rule id: {ruleid}, version: '{ruleversion}', expected: '{crsversion}'",
                            rule="version",
                        )
