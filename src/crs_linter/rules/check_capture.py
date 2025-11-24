import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CheckCapture(Rule):
    """Check that every chained rule has a `capture` action if it uses TX.N variable.

    This rule ensures that chained rules using captured transaction variables
    (TX:0, TX:1, TX:2, etc.) have a corresponding `capture` action in a
    previous rule in the chain.

    Example of a passing rule:
        SecRule ARGS "@rx attack" \\
            "id:2,\\
            phase:2,\\
            deny,\\
            capture,\\
            t:none,\\
            nolog,\\
            chain"
            SecRule TX:1 "@eq attack"

    Example of a failing rule (missing capture):
        SecRule ARGS "@rx attack" \\
            "id:3,\\
            phase:2,\\
            deny,\\
            t:none,\\
            nolog,\\
            chain"
            SecRule TX:0 "@eq attack"  # Fails: uses TX:0 without prior capture
    """

    def __init__(self):
        super().__init__()
        self.name = "capture"  # Override the default name
        self.success_message = "No rule uses TX.N without capture action."
        self.error_message = "There are one or more rules using TX.N without capture action."
        self.error_title = "capture is missing"
        self.args = ("data",)

    def check(self, data):
        """
        check that every chained rule has a `capture` action if it uses TX.N variable
        """
        chained = False
        ruleid = 0
        chainlevel = 0
        capture_level = None
        re_number = re.compile(r"^\d$")
        has_capture = False
        use_captured_var = False
        captured_var_chain_level = 0
        for d in data:
            # only the SecRule object is relevant
            if d["type"].lower() == "secrule":
                for v in d["variables"]:
                    if v["variable"].lower() == "tx" and re_number.match(
                        v["variable_part"]
                    ):
                        # only the first occurrence required
                        if not use_captured_var:
                            use_captured_var = True
                            captured_var_chain_level = chainlevel
                if "actions" in d:
                    if not chained:
                        ruleid = 0
                        chainlevel = 0
                    else:
                        chained = False
                    for a in d["actions"]:
                        if a["act_name"] == "id":
                            ruleid = int(a["act_arg"])
                        if a["act_name"] == "chain":
                            chained = True
                            chainlevel += 1
                        if a["act_name"] == "capture":
                            capture_level = chainlevel
                            has_capture = True
                    if ruleid > 0 and not chained:  # end of chained rule
                        if use_captured_var:
                            # we allow if target with TX:N is in the first rule
                            # of a chained rule without 'capture'
                            if captured_var_chain_level > 0:
                                if (
                                    not has_capture
                                    or captured_var_chain_level < capture_level
                                ):
                                    yield LintProblem(
                                        line=a["lineno"],
                                        end_line=a["lineno"],
                                        desc=f"rule uses TX.N without capture; rule id: {ruleid}",
                                        rule="capture",
                                    )
                        # clear variables
                        chained = False
                        chainlevel = 0
                        has_capture = False
                        capture_level = 0
                        captured_var_chain_level = 0
                        use_captured_var = False
                        ruleid = 0

