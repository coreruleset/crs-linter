from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class LowercaseIgnorecase(Rule):
    """Check for combined transformation and ignorecase patterns."""

    def __init__(self):
        super().__init__()
        self.success_message = "No combined transformation and ignorecase patterns found."
        self.error_message = "Found combined transformation and ignorecase pattern(s)"
        self.error_title = "combined transformation and ignorecase"
        self.args = ("data",)

    def check(self, data):
        """check for combined transformation and ignorecase patterns"""
        ruleid = 0
        for d in data:
            if d["type"].lower() == "secrule":
                if d["operator"] == "@rx":
                    regex = d["operator_argument"]
                    if regex.startswith("(?i)"):
                        if "actions" in d:
                            for a in d["actions"]:
                                if a["act_name"] == "id":
                                    ruleid = int(a["act_arg"])
                                if a["act_name"] == "t":
                                    # check the transform is valid
                                    if a["act_arg"].lower() == "lowercase":
                                        yield LintProblem(
                                            line=a["lineno"],
                                            end_line=a["lineno"],
                                            desc=f'rule uses (?i) in combination with t:lowercase: \'{a["act_arg"]}\'; rule id: {ruleid}',
                                            rule="lowercase_ignorecase",
                                        )
