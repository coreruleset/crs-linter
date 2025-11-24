from crs_linter.lint_problem import LintProblem
from crs_linter.utils import get_id
from crs_linter.rule import Rule

ACTIONS_ORDER = [
    "id",  # 0
    "phase",  # 1
    "allow",
    "block",
    "deny",
    "drop",
    "pass",
    "proxy",
    "redirect",
    "status",
    "capture",  # 10
    "t",
    "log",
    "nolog",
    "auditlog",
    "noauditlog",
    "msg",
    "logdata",
    "tag",
    "sanitisearg",
    "sanitiserequestheader",  # 20
    "sanitisematched",
    "sanitisematchedbytes",
    "ctl",
    "ver",
    "severity",
    "multimatch",
    "initcol",
    "setenv",
    "setvar",
    "expirevar",  # 30
    "chain",
    "skip",
    "skipafter",
]


class OrderedActions(Rule):
    """Check that actions are in the correct order.

    This rule verifies that actions in rules follow the CRS-specified order.
    The first action must be 'id', followed by 'phase', and then other
    actions in their designated order.

    Example of a failing rule (wrong action order):
        SecRule REQUEST_URI "@beginsWith /index.php" \\
            "phase:1,\\  # Wrong: phase should come after id
            id:1,\\
            deny,\\
            t:none,\\
            nolog"

    Example of a correct rule:
        SecRule REQUEST_URI "@beginsWith /index.php" \\
            "id:1,\\  # Correct: id comes first
            phase:1,\\  # Correct: phase comes second
            deny,\\
            t:none,\\
            nolog"
    """

    def __init__(self):
        super().__init__()
        self.success_message = "Action order check ok."
        self.error_message = "Action order check found error(s)"
        self.error_title = "Action order check"
        self.args = ("data",)

    def check(self, data):
        chained = False

        for d in data:
            if "actions" in d:
                max_order = 0  # maximum position of read actions
                if not chained:
                    current_rule_id = get_id(d["actions"])
                else:
                    chained = False

                for index, a in enumerate(d["actions"]):
                    action = a["act_name"].lower()
                    # get the line number of rule
                    current_lineno = a["lineno"]

                    # check if chained
                    if a["act_name"] == "chain":
                        chained = True

                    # get the index of action from the ordered list
                    # above from constructor
                    try:
                        act_idx = ACTIONS_ORDER.index(action)
                    except ValueError:
                        yield LintProblem(
                            line=current_lineno,
                            end_line=current_lineno,
                            desc=f'action "{action}" at pos {index - 1} is in the wrong order: "{action}" at pos {index}; rule id: {current_rule_id}',
                            rule="ordered_actions",
                        )

                    # if the index of current action is @ge than the previous
                    # max value, load it into max_order
                    if act_idx >= max_order:
                        max_order = act_idx
                    else:
                        # action is the previous action's position in list
                        # act_idx is the current action's position in list
                        # if the prev is @gt actually, means it's at wrong position
                        if act_idx < max_order:
                            yield LintProblem(
                                line=current_lineno,
                                end_line=current_lineno,
                                desc=f'action "{action}" at pos {index - 1} is in the wrong order: "{action}" at pos {index}; rule id: {current_rule_id}',
                                rule="ordered_actions",
                            )

