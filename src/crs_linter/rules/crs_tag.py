
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CrsTag(Rule):
    """Check that every rule has a `tag:'OWASP_CRS'` action."""

    def __init__(self):
        super().__init__()
        self.success_message = "No rule without OWASP_CRS tag."
        self.error_message = "There are one or more rules without OWASP_CRS tag"
        self.error_title = "'tag:OWASP_CRS' is missing"
        self.args = ("data",)

    def check(self, data):
        """
        check that every rule has a `tag:'OWASP_CRS'` action
        """
        chained = False
        ruleid = 0
        has_crs = False
        for d in data:
            if "actions" in d:
                chainlevel = 0

                if not chained:
                    ruleid = 0
                    has_crs = False
                    chainlevel = 0
                else:
                    chained = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                        chainlevel += 1
                    if a["act_name"] == "tag":
                        if chainlevel == 0:
                            if a["act_arg"] == "OWASP_CRS":
                                has_crs = True
                if ruleid > 0 and not has_crs:
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule does not have tag with value 'OWASP_CRS'; rule id: {ruleid}",
                        rule="crs_tag",
                    )


