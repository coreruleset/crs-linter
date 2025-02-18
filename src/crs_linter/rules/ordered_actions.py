from crs_linter.linter import LintProblem

ORDERED_ACTIONS = [
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

def check(data):
    global act_idx, current_rule_id
    chained = False

    for d in data:
        if "actions" in d:
            max_order = 0  # maximum position of read actions
            if not chained:
                current_rule_id = _get_id(d["actions"])
            else:
                chained = False

            for index, a in enumerate(d["actions"]):
                action = a["act_name"].lower()
                # get the 'id' of rule
                current_lineno = a["lineno"]

                # check if chained
                if a["act_name"] == "chain":
                    chained = True

                # get the index of action from the ordered list
                # above from constructor
                try:
                    act_idx = ORDERED_ACTIONS.index(action)
                except ValueError:
                    yield LintProblem(
                        line=current_lineno,
                        end_line=current_lineno,
                        rule_id=current_rule_id,
                        desc=f'action "{action}" at pos {index - 1} is in the wrong order: "{action}" at pos {index}',
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
                            rule_id=current_rule_id,
                            desc=f'action "{action}" at pos {index - 1} is in the wrong order: "{action}" at pos {index}',
                            rule="ordered_actions",
                        )

