from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class Deprecated(Rule):
    """Check for deprecated patterns in rules."""

    def __init__(self):
        super().__init__()
        self.success_message = "No deprecated patterns found."
        self.error_message = "Found deprecated pattern(s)"
        self.error_title = "deprecated pattern"
        self.args = ("data",)

    def check(self, data):
        """check for deprecated patterns in rules"""
        for d in data:
            if "actions" in d:
                current_ruleid = 0
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        current_ruleid = int(a["act_arg"])

                    # check if action is ctl:auditLogParts (deprecated)
                    if (
                        a["act_name"].lower() == "ctl"
                        and a["act_arg"].lower() == "auditlogparts"
                    ):
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"ctl:auditLogParts action is deprecated; rule id: {current_ruleid}",
                            rule="deprecated",
                        )
