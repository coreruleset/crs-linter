from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class Deprecated(Rule):
    """Check for deprecated patterns in rules.

    This is a general-purpose rule for checking deprecated patterns that may be
    removed in future CRS versions. Currently checks for ctl:auditLogParts.

    Example of a failing rule (using deprecated ctl:auditLogParts):
        SecRule TX:sql_error_match "@eq 1" \\
            "id:1,\\
            phase:4,\\
            block,\\
            capture,\\
            t:none,\\
            ctl:auditLogParts=+E"  # Fails: ctl:auditLogParts is deprecated

    The ctl:auditLogParts action is no longer supported in CRS (see PR #3034).

    Note: This overlaps with ctl_audit_log.py which checks the same pattern but
    treats it as "not allowed" rather than "deprecated". Consider consolidating
    these rules if they serve the same purpose.
    """

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
