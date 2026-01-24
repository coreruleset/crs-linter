from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class NoNegatedRequestCookies(Rule):
    """Check that SecRule directives don't use negated REQUEST_COOKIES targets.

    This rule enforces the policy that cookie exclusions should not be
    implemented using !REQUEST_COOKIES in SecRule directives. Instead,
    cookie exclusions should be moved to separate post-CRS files using
    SecRuleUpdateTargetById directives.

    Example of a failing rule (old pattern - not allowed):
        SecRule !REQUEST_COOKIES:session_id|ARGS:foo "@rx attack" \\
            "id:942100,\\
            phase:2,\\
            block"  # Fails: uses !REQUEST_COOKIES

    Example of the correct approach (new pattern):

    In the main rule file:
        SecRule REQUEST_COOKIES|ARGS:foo "@rx attack" \\
            "id:942100,\\
            phase:2,\\
            block"

    In a separate post-CRS configuration file:
        SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:session_id"

    See: https://github.com/coreruleset/coreruleset/pull/4378
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No rules use negated REQUEST_COOKIES targets."
        self.error_message = "Found rule(s) using negated REQUEST_COOKIES targets"
        self.error_title = "negated REQUEST_COOKIES target"
        self.args = ("data",)

    def check(self, data):
        """Check for negated REQUEST_COOKIES targets in SecRule directives."""
        for d in data:
            if d["type"].lower() == "secrule":
                current_ruleid = 0

                # Get the rule ID first
                if "actions" in d:
                    for a in d["actions"]:
                        if a["act_name"] == "id":
                            current_ruleid = int(a["act_arg"])
                            break

                # Check all variables/targets in the rule
                if "variables" in d:
                    for v in d["variables"]:
                        # Check if this is a negated REQUEST_COOKIES target
                        if (
                            v["variable"].upper() == "REQUEST_COOKIES"
                            and v.get("negated", False)
                        ):
                            yield LintProblem(
                                line=d["lineno"],
                                end_line=d["lineno"],
                                desc=f"SecRule uses negated REQUEST_COOKIES target (!REQUEST_COOKIES). "
                                     f"Move cookie exclusions to post-CRS files using SecRuleUpdateTargetById instead; "
                                     f"rule id: {current_ruleid}",
                                rule="no_negated_request_cookies",
                            )
                            # Only report once per rule, even if multiple negated REQUEST_COOKIES targets
                            break
