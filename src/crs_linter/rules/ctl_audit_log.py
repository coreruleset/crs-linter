from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CtlAuditLog(Rule):
    """Check there is no ctl:auditLogParts action in any rules."""

    def __init__(self):
        super().__init__()
        self.success_message = "no 'ctl:auditLogParts' action found."
        self.error_message = "Found 'ctl:auditLogParts' action"
        self.error_title = "'ctl:auditLogParts' isn't allowed in CRS"
        self.args = ("data",)

    def check(self, data):
        """check there is no ctl:auditLogParts action in any rules"""
        for d in data:
            if "actions" in d:
                current_ruleid = 0
                for a in d["actions"]:
                    # get the 'id' of rule
                    if a["act_name"] == "id":
                        current_ruleid = int(a["act_arg"])

                    # check if action is ctl:auditLogParts
                    if (
                        a["act_name"].lower() == "ctl"
                        and a["act_arg"].lower() == "auditlogparts"
                    ):
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"ctl:auditLogParts action is not allowed; rule id: {current_ruleid}",
                            rule="ctl_audit_log",
                        )
