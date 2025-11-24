from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule
from crs_linter.utils import get_id


class RuleTests(Rule):
    """Check that rules have corresponding test cases.

    This rule verifies that each rule has at least one corresponding test
    case in the test suite. Rules without tests are flagged to ensure
    adequate test coverage.

    The check skips:
    - Paranoia level control rules (rule IDs with last two digits < 100)
    - Rules in the exclusion list (configured via -E flag)

    Example of a failing rule (no corresponding tests):
        SecRule REQUEST_URI "@rx malicious" \\
            "id:942100,\\  # Fails if no test case references rule 942100
            phase:2,\\
            block,\\
            t:none,\\
            tag:OWASP_CRS"

    To fix: Add a test case to your test suite that exercises this rule.

    Use the -E flag to provide a file with rule ID prefixes that should be
    excluded from this check.
    """

    def __init__(self):
        super().__init__()
        self.success_message = "All rules have tests."
        self.error_message = "There are one or more rules without tests."
        self.error_title = "no tests"
        self.args = ("data", "test_cases", "exclusion_list")

    def check(self, data, test_cases=None, exclusion_list=None):
        """
        Check that rules have corresponding test cases
        """
        if test_cases is None:
            test_cases = {}
        if exclusion_list is None:
            exclusion_list = []
        
        for d in data:
            # only SecRule counts
            if d['type'] == "SecRule":
                # Use get_id() helper to extract rule ID
                rid = get_id(d['actions'])
                if rid > 0:  # Only process if we found a valid ID
                    srid = str(rid)
                    if (rid % 1000) >= 100:   # skip the PL control rules
                        # also skip these hardcoded rules
                        need_check = True
                        for excl in exclusion_list:
                            # exclude full rule IDs or rule ID prefixes
                            if srid[:len(excl)] == excl:
                                need_check = False
                        if need_check:
                            # if there is no test cases, just print it
                            if rid not in test_cases:
                                # Find the line number of the id action for reporting
                                lineno = d.get('lineno', 0)
                                for a in d['actions']:
                                    if a['act_name'] == "id":
                                        lineno = a['lineno']
                                        break
                                yield LintProblem(
                                    line=lineno,
                                    end_line=lineno,
                                    desc=f"rule does not have any tests; rule id: {rid}",
                                    rule="rule_tests",
                                )
