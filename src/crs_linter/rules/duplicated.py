from crs_linter.lint_problem import LintProblem
from crs_linter.utils import get_id
from crs_linter.rule import Rule


class DuplicatedIds(Rule):
    """Check for duplicated rule IDs.

    This rule ensures that each rule has a unique ID across all configuration
    files in the ruleset.

    Example of failing rules (duplicate IDs):
        SecRule ARGS "@rx foo" \\
            "id:1001,\\
            phase:2,\\
            block,\\
            capture,\\
            t:none"

        SecRule ARGS_NAMES "@rx bar" \\
            "id:1001,\\  # Fails: ID 1001 is already used above
            phase:2,\\
            block,\\
            capture,\\
            t:none"
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No duplicate IDs found."
        self.error_message = "Found duplicated ID(s)"
        self.error_title = "'id' is duplicated"
        self.args = ("data", "ids", "filename")

    def check(self, data, ids, filename):
        """Checks the duplicated rule ID"""
        for d in data:
            if "actions" in d:
                rule_id = get_id(d["actions"])
                # Skip rules without an ID (get_id returns 0 when no ID is found)
                if rule_id == 0:
                    continue
                    
                if rule_id in ids:
                    # Found a duplicate!
                    yield LintProblem(
                        line=0,  # Line number not available in this context
                        end_line=0,
                        desc=f"id {rule_id} is duplicated, previous place: {ids[rule_id]['fname']}:{ids[rule_id]['lineno']}",
                        rule="duplicated",
                    )
                else:
                    # First occurrence - add to ids dict for future duplicate detection
                    # Get the line number from the actions
                    lineno = 0
                    for action in d["actions"]:
                        if action["act_name"] == "id":
                            lineno = action.get("lineno", 0)
                            break
                    ids[rule_id] = {
                        "fname": filename,
                        "lineno": lineno
                    }
