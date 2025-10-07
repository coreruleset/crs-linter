from crs_linter.lint_problem import LintProblem
from crs_linter.utils import get_id


def check(data, ids):
    """ Checks the duplicated rule ID """
    for d in data:
        if "actions" in d:
            rule_id = get_id(d["actions"])
            if rule_id in ids:
                yield LintProblem(
                    rule_id,
                    desc="id %d is duplicated, previous place: %s:%d"
                )
