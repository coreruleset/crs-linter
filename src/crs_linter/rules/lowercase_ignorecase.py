from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class LowercaseIgnorecase(Rule):
    """Check for combined transformation and ignorecase patterns.

    This rule detects when rules use both the t:lowercase transformation and
    the (?i) case-insensitive regex flag together. This combination is
    redundant and should be avoided - use one or the other.

    Example of a failing rule (combining t:lowercase and (?i)):
        SecRule ARGS "@rx (?i)foo" \\
            "id:1,\\
            phase:1,\\
            pass,\\
            t:lowercase,\\  # Fails: redundant with (?i) flag
            nolog"

    The rule should use either:
    - t:lowercase with a case-sensitive regex: "@rx foo"
    - (?i) flag without t:lowercase transformation
    """

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
