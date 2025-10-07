from crs_linter.lint_problem import LintProblem


def check(data, ids=None):
    """
    Check for duplicated rule IDs
    """
    if ids is None:
        ids = {}
    
    for d in data:
        if "actions" in d:
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
                    if ruleid in ids:
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"id {ruleid} is duplicated, previous place: {ids[ruleid]['fname']}:{ids[ruleid]['lineno']}",
                            rule="duplicated_ids",
                        )
                    else:
                        # This would be handled by the caller to update the ids dict
                        pass
