import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class StandaloneTxn(Rule):
    """Check that TX.N variables are not used as targets in standalone rules.

    This rule prevents TX.N capture group variables (TX:0, TX:1, TX:2, etc.)
    from being used as rule targets in standalone rules. Standalone rules have
    no control over what values exist in TX.N from previous unrelated rules,
    making such usage unpredictable and error-prone.

    TX.N variables should only be used in chained rules where the parent rule
    in the chain sets the value (typically via regex matching).

    Example of a failing rule (standalone rule using TX.N):
        SecRule "TX:4" "@eq 1" \\
            "id:3,\\
            phase:2,\\
            deny"  # Fails: standalone rule using TX:4

    Example of a passing rule (chained rule using TX.N):
        SecRule ARGS "@rx (ab|cd)?(ef)" \\
            "id:1,\\
            phase:2,\\
            deny,\\
            chain"
            SecRule "TX:1" "@eq ef"  # OK: TX:1 used in chained rule

    Note: This check complements the CheckCapture rule, which ensures that
    TX.N usage requires a capture action. This rule specifically addresses
    the issue of TX.N in standalone rules where values are unpredictable.
    """

    def __init__(self):
        super().__init__()
        self.name = "standalonetxn"
        self.success_message = "No standalone rules use TX.N as target."
        self.error_message = "One or more standalone rules use TX.N as target."
        self.error_title = "TX.N in standalone rule"
        self.args = ("data",)

        # Pattern to match numeric TX variables: TX:0, TX:1, etc.
        self.txn_pattern = re.compile(r"^\d$")

    def check(self, data):
        """
        Check that TX.N variables are not used as targets in standalone rules.

        A rule is considered standalone if it's not preceded by a rule with
        the 'chain' action. TX.N targets are only allowed in chained rules.
        """
        is_chained = False  # Tracks if current rule is part of a chain
        current_rule_id = 0

        for d in data:
            # Only check SecRule directives
            if d["type"].lower() != "secrule":
                continue

            # Check if this rule uses TX.N as a target
            uses_txn_target = False
            for v in d["variables"]:
                if (v["variable"].lower() == "tx" and
                    self.txn_pattern.match(v["variable_part"])):
                    uses_txn_target = True
                    break

            # If this is a standalone rule using TX.N, flag it
            if uses_txn_target and not is_chained:
                # Get rule ID for better error message
                rule_id = current_rule_id
                if "actions" in d:
                    for a in d["actions"]:
                        if a["act_name"] == "id":
                            rule_id = int(a["act_arg"])
                            break

                yield LintProblem(
                    line=d.get("lineno", 0),
                    end_line=d.get("lineno", 0),
                    desc=f"standalone rule uses TX.N as target; rule id: {rule_id}",
                    rule="standalonetxn",
                )

            # Update chained state for next rule
            # Check if this rule has a 'chain' action
            if "actions" in d:
                has_chain_action = False
                for a in d["actions"]:
                    if a["act_name"] == "id":
                        current_rule_id = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        has_chain_action = True
                        break

                # After processing this rule:
                # - If it has 'chain', the NEXT rule will be chained
                # - If it doesn't have 'chain', the chain ends
                is_chained = has_chain_action
