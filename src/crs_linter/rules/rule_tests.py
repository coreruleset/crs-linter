from crs_linter.lint_problem import LintProblem


def check(data, test_cases=None, exclusion_list=None):
    """
    Check that rules have corresponding test cases
    """
    if test_cases is None:
        test_cases = {}
    if exclusion_list is None:
        exclusion_list = []
    
    for d in data:
        # only SecRule counts
        if d['type'] == "SecRule":
            for a in d['actions']:
                # find the `id` action
                if a['act_name'] == "id":
                    # get the argument of the action
                    rid = int(a['act_arg']) # int
                    srid = a['act_arg']     # string
                    if (rid%1000) >= 100:   # skip the PL control rules
                        # also skip these hardcoded rules
                        need_check = True
                        for excl in exclusion_list:
                            # exclude full rule IDs or rule ID prefixes
                            if srid[:len(excl)] == excl:
                                need_check = False
                        if need_check:
                            # if there is no test cases, just print it
                            if rid not in test_cases:
                                yield LintProblem(
                                    line=a['lineno'],
                                    end_line=a['lineno'],
                                    
                                    desc=f"rule does not have any tests; rule id: {rid}",
                                    rule="rule_tests",
                                )
