from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class Version(Rule):
    """Check that every rule has a `ver` action with the correct version.

    This rule verifies that all rules have a 'ver' action with the correct
    CRS version string. The version can be specified manually using the -v
    flag, or automatically extracted from git tags using 'git describe --tags'.

    Example of failing rules:
        # Missing 'ver' action
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:OWASP_CRS"  # Fails: no ver action

        # Incorrect 'ver' value
        SecRule REQUEST_URI "@rx index.php" \\
            "id:2,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:OWASP_CRS,\\
            ver:OWASP_CRS/1.0.0-dev"  # Fails if expected version is 4.6.0-dev

    Example of a correct rule:
        SecRule REQUEST_URI "@rx index.php" \\
            "id:3,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:OWASP_CRS,\\
            ver:'OWASP_CRS/4.6.0-dev'"
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No rule without correct ver action."
        self.error_message = "There are one or more rules with incorrect ver action."
        self.error_title = "ver is missing / incorrect"
        self.args = ("data", "version")

    def check(self, data, version):
        """
        check that every rule has a `ver` action
        """
        chained = False
        ruleid = 0
        has_ver = False
        ver_is_ok = False
        crsversion = version
        ruleversion = ""
        for d in data:
            if "actions" in d:
                chainlevel = 0

                if not chained:
                    ruleid = 0
                    has_ver = False
                    ver_is_ok = False
                    chainlevel = 0
                else:
                    chained = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                        chainlevel += 1
                    if a["act_name"] == "ver":
                        if chainlevel == 0:
                            has_ver = True
                            if a["act_arg"] == version:
                                ver_is_ok = True
                            else:
                                ruleversion = a["act_arg"]
                if ruleid > 0 and chainlevel == 0:
                    if not has_ver:
                        yield LintProblem(
                            line=a["lineno"],
                            end_line=a["lineno"],
                            desc=f"rule does not have 'ver' action; rule id: {ruleid}",
                            rule="version",
                        )
                    else:
                        if not ver_is_ok:
                            yield LintProblem(
                                line=a["lineno"],
                                end_line=a["lineno"],
                                desc=f"rule's 'ver' action has incorrect value; rule id: {ruleid}, version: '{ruleversion}', expected: '{crsversion}'",
                                rule="version",
                            )
