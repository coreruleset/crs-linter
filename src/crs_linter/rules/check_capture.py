import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CheckCapture(Rule):
    """Check that rules using TX.N variables have a corresponding `capture` action.

    This rule ensures that captured transaction variables (TX:0, TX:1, TX:2, etc.)
    are only used when a `capture` action has been defined in the rule chain.

    TX.N variables can be referenced in multiple ways:
    1. As a rule target: `SecRule TX:1 "@eq attack"`
    2. In action arguments: `msg:'Matched: %{TX.1}'`, `logdata:'Data: %{TX.0}'`
    3. In operator arguments: `@rx %{TX.1}`
    4. In setvar assignments: `setvar:tx.foo=%{TX.1}`

    Example of a passing rule (with capture):
        SecRule ARGS "@rx (attack)" \\
            "id:2,\\
            phase:2,\\
            deny,\\
            capture,\\
            msg:'Attack detected: %{TX.1}',\\
            logdata:'Pattern: %{TX.0}',\\
            chain"
            SecRule TX:1 "@eq attack"

    Example of a failing rule (missing capture for target):
        SecRule ARGS "@rx attack" \\
            "id:3,\\
            phase:2,\\
            deny,\\
            t:none,\\
            nolog,\\
            chain"
            SecRule TX:0 "@eq attack"  # Fails: uses TX:0 without capture

    Example of a failing rule (missing capture for action argument):
        SecRule ARGS "@rx attack" \\
            "id:4,\\
            phase:2,\\
            deny,\\
            msg:'Matched: %{TX.1}'"  # Fails: references TX.1 without capture

    This check addresses the issue found in CRS PR #4265 where %{TX.N} was
    used in action arguments without verifying that capture was defined.
    """

    def __init__(self):
        super().__init__()
        self.name = "capture"  # Override the default name
        self.success_message = "No rule uses TX.N without capture action."
        self.error_message = "There are one or more rules using TX.N without capture action."
        self.error_title = "capture is missing"
        self.args = ("data",)

        # Regex patterns for detecting TX.N references
        self.target_pattern = re.compile(r"^\d$")  # For target variables: TX:1
        self.expansion_pattern = re.compile(
            r"%\{TX[.:](\d)\}",  # Matches %{TX.0} or %{TX:1}
            re.IGNORECASE
        )

        # Actions that commonly use variable expansion
        self.actions_to_check = {
            'msg', 'logdata', 'setvar', 'tag'
        }

    def check(self, data):
        """
        Check that TX.N variables are only used when capture action is defined.

        This checks for TX.N references in:
        - Rule targets (existing functionality)
        - Action arguments (msg, logdata, setvar, tag)
        - Operator arguments
        """
        chained = False
        ruleid = 0
        chainlevel = 0
        capture_level = None
        has_capture = False
        use_captured_var = False
        use_captured_var_in_expansion = False  # Track if TX.N is used in expansion
        captured_var_chain_level = 0

        for d in data:
            # only the SecRule object is relevant
            if d["type"].lower() != "secrule":
                continue

            # Check 1: TX.N as target variable (existing check)
            for v in d["variables"]:
                if (v["variable"].lower() == "tx" and
                    self.target_pattern.match(v["variable_part"])):
                    # only the first occurrence required
                    if not use_captured_var:
                        use_captured_var = True
                        captured_var_chain_level = chainlevel

            # Check 2: TX.N in operator arguments
            if "operator_argument" in d and d["operator_argument"]:
                op_arg = d["operator_argument"]
                if self.expansion_pattern.search(op_arg):
                    if not use_captured_var:
                        use_captured_var = True
                        captured_var_chain_level = chainlevel
                    # Always track that TX.N is used in an expansion, even if it
                    # was already seen as a target elsewhere in the rule chain.
                    use_captured_var_in_expansion = True

            # Check 3: TX.N in action arguments
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

                    # Check if action argument (or value) contains TX.N reference
                    if a["act_name"] in self.actions_to_check:
                        for field in ("act_arg", "act_arg_val"):
                            value = a.get(field)
                            if value and self.expansion_pattern.search(value):
                                if not use_captured_var:
                                    use_captured_var = True
                                    use_captured_var_in_expansion = True
                                    captured_var_chain_level = chainlevel
                                break

                # End of rule/chain - validate
                if ruleid > 0 and not chained:
                    if use_captured_var:
                        # Rules for requiring capture:
                        # 1. TX.N as target in chained rule (not first) - require capture (original check)
                        # 2. TX.N in expansion (%{TX.N}) anywhere - require capture (new check for issue #69)
                        should_error = False

                        if captured_var_chain_level > 0:
                            # TX.N used in a chained rule (not the first)
                            if not has_capture or captured_var_chain_level < capture_level:
                                should_error = True
                        elif use_captured_var_in_expansion and not has_capture:
                            # TX.N used in expansion (%{TX.N}) without capture
                            # This is the new check for issue #69
                            should_error = True

                        if should_error:
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
                    use_captured_var_in_expansion = False
                    ruleid = 0

