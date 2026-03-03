from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class PassNolog(Rule):
    """Check that rules using the `pass` action also include `nolog`.

    When a rule uses the `pass` disruptive action (allowing the request to
    continue), it should also include `nolog` to prevent excessive log spam.
    Rule logging is only meaningful for blocking rules or for debugging
    purposes.

    Example of a failing rule (pass without nolog):
        SecRule ARGS "@rx foo" \\
            "id:1,\\
            phase:2,\\
            pass,\\
            t:none"  # Fails: pass without nolog

    Example of a correct rule:
        SecRule ARGS "@rx foo" \\
            "id:2,\\
            phase:2,\\
            pass,\\
            t:none,\\
            nolog"  # OK: nolog accompanies pass

    Note: This check applies to any directive that supports actions, including
    SecRule and SecAction.
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No rules use 'pass' without 'nolog'."
        self.error_message = "Found rule(s) using 'pass' without 'nolog'"
        self.error_title = "pass without nolog"
        self.args = ("data",)

    def check(self, data):
        for d in data:
            if "actions" in d:
                current_ruleid = None
                has_pass = False
                has_nolog = False
                pass_lineno = 0

                for a in d["actions"]:
                    if a["act_name"] == "id":
                        current_ruleid = int(a["act_arg"])
                    if a["act_name"].lower() == "pass":
                        has_pass = True
                        pass_lineno = a["lineno"]
                    if a["act_name"].lower() == "nolog":
                        has_nolog = True

                if has_pass and not has_nolog:
                    rule_id_str = str(current_ruleid) if current_ruleid is not None else "unknown"
                    yield LintProblem(
                        line=pass_lineno,
                        end_line=pass_lineno,
                        desc=f"rule uses 'pass' without 'nolog'; rule id: {rule_id_str}",
                        rule="passnolog",
                    )
