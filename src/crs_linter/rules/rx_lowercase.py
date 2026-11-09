from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule
from crs_linter.rules.lowercase_ignorecase import IGNORECASE_FLAG


class RxLowercase(Rule):
    """Check that @rx rules use the (?i) flag instead of t:lowercase.

    CRS matches case-insensitively with the (?i) regex flag (`##!+ i` in
    regex-assembly files). t:lowercase is kept for operators without a flag,
    such as @within, @streq or @contains. Unlike t:lowercase, (?i) keeps the
    original casing in MATCHED_VAR and logdata, and does not depend on the
    transformation pipeline.

    Example of a failing rule (t:lowercase with @rx):
        SecRule ARGS "@rx foo" \\
            "id:1,\\
            phase:1,\\
            pass,\\
            t:lowercase,\\  # Fails: use "@rx (?i)foo" instead
            nolog"

    Rules that need the lowercased value itself (a capture stored for a
    later @within, or a case-sensitive transformation such as t:jsDecode
    after t:lowercase) are exempted with:
        #crs-linter:ignore:rx_lowercase

    Rules that also use (?i) are reported by lowercase_ignorecase instead.

    This check is opt-in, so older CRS releases and plugins are not affected.
    Enable it in the config file passed with -c:
        enable_checks = ["rx_lowercase"]
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No @rx rule uses t:lowercase."
        self.error_message = "Found @rx rule(s) using t:lowercase"
        self.error_title = "t:lowercase with @rx"
        self.args = ("data",)
        self.opt_in = True

    def check(self, data):
        """check for t:lowercase on @rx rules"""
        ruleid = 0
        for d in data:
            if d["type"].lower() != "secrule" or "actions" not in d:
                continue
            for a in d["actions"]:
                if a["act_name"] == "id":
                    ruleid = int(a["act_arg"])
            if d["operator"] != "@rx" or IGNORECASE_FLAG.search(d["operator_argument"]):
                continue
            for a in d["actions"]:
                if a["act_name"] == "t" and a["act_arg"].lower() == "lowercase":
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule uses t:lowercase with @rx, use the (?i) flag instead; rule id: {ruleid}",
                        rule="rx_lowercase",
                    )
