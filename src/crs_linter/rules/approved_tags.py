from crs_linter.lint_problem import LintProblem

def check(data, tags):
    """
    check that only tags from the util/APPROVED_TAGS file are used
    """
    chained = False
    ruleid = 0
    for d in data:
        if "actions" in d:
            for a in d["actions"]:
               if a["act_name"] == "tag":
                    tag = a["act_arg"]
                    # check wheter tag is in tagslist
                    if tags.count(tag) == 0:
                        yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f'rule uses unknown tag: "{tag}"; only tags registered in the util/APPROVED_TAGS file may be used; rule id: {ruleid}',
                                rule="approved_tags"
                            )
