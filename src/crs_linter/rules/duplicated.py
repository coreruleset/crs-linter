from crs_linter.lint_problem import LintProblem
from crs_linter.utils import get_id
from crs_linter.rule import Rule


class DuplicatedIds(Rule):
    """Check for duplicated rule IDs."""

    def __init__(self):
        super().__init__()
        self.success_message = "No duplicate IDs found."
        self.error_message = "Found duplicated ID(s)"
        self.error_title = "'id' is duplicated"
        self.args = ("data", "ids")

    def check(self, data, ids):
        """Checks the duplicated rule ID"""
        for d in data:
            if "actions" in d:
                rule_id = get_id(d["actions"])
                if rule_id in ids:
                    yield LintProblem(
                        line=0,  # Line number not available in this context
                        end_line=0,
                        desc=f"id {rule_id} is duplicated, previous place: {ids[rule_id]['fname']}:{ids[rule_id]['lineno']}",
                        rule="duplicated",
                    )
