import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule

# Operators that implicitly anchor to the start (or full string) of the value
_START_ANCHORED_OPERATORS = frozenset({"beginswith", "streq"})

# Matches @rx patterns anchored to start (^) that lack the full optional (?:json\.)?
# prefix. The lookahead requires the complete token — group start, literal "json",
# optional backslash, literal dot, group close, and the "?" quantifier — so that
# forms like "^(?:json\.)foo" (mandatory, not optional) or "^(?:jsonx)?" (wrong
# name) are still flagged.
_MISSING_JSON_PREFIX_RE = re.compile(r"^\^(?!\(\?:json\\?\.\)\?)")


class ArgsNamesJsonPrefix(Rule):
    """Check that ARGS_NAMES rules with start-anchored operators include a (?:json\\.)? prefix.

    libModSecurity3 and Coraza prefix JSON body parameter names with 'json.' (e.g.
    the field 'username' in a JSON payload becomes 'json.username' in ARGS_NAMES),
    whereas ModSecurity2 does not add this prefix. Rules that anchor to the start of
    the parameter name must account for both forms by using '(?:json\\.)?'.

    Affected operators when combined with ARGS_NAMES:
    - @rx:         when the pattern starts with '^' without a '(?:json...)' prefix
    - @beginsWith: always start-anchored
    - @streq:      always full-string match (equivalent to '^...$')

    Example of a failing rule (@rx without json prefix):
        SecRule ARGS_NAMES "@rx ^username$" \\
            "id:1,phase:2,deny,t:none"
        # Fails: '^username$' will not match 'json.username' in JSON payloads on
        #        libModSecurity3/Coraza

    Example of a failing rule (@beginsWith):
        SecRule ARGS_NAMES "@beginsWith username" \\
            "id:2,phase:2,deny,t:none"
        # Fails: cannot match the 'json.' prefix; replace with @rx and (?:json\\.)?

    Example of the correct approach (@rx with json prefix):
        SecRule ARGS_NAMES "@rx ^(?:json\\.)?username$" \\
            "id:3,phase:2,deny,t:none"
        # OK: matches both 'username' (ModSec2) and 'json.username' (libModSec3/Coraza)

    See: https://github.com/coreruleset/crs-linter/issues/154
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No ARGS_NAMES rules missing (?:json\\.)? prefix on start-anchored patterns."
        self.error_message = "Found ARGS_NAMES rule(s) missing (?:json\\.)? on start-anchored patterns"
        self.error_title = "ARGS_NAMES missing json prefix"
        self.args = ("data",)

    def check(self, data):
        """Check ARGS_NAMES rules for a missing (?:json\\.)? prefix on start-anchored patterns."""
        chained = False
        current_ruleid = 0

        for d in data:
            if d["type"].lower() != "secrule":
                continue

            if "actions" in d:
                if not chained:
                    current_ruleid = 0
                else:
                    chained = False

                for a in d["actions"]:
                    if a["act_name"] == "id":
                        try:
                            current_ruleid = int(a["act_arg"])
                        except (ValueError, TypeError):
                            current_ruleid = 0
                    if a["act_name"] == "chain":
                        chained = True

            has_args_names = any(
                v["variable"].upper() == "ARGS_NAMES" and not v.get("negated", False)
                for v in d.get("variables", [])
            )
            if not has_args_names:
                continue

            operator_raw = d.get("operator", "")
            if not operator_raw:
                continue

            operator = operator_raw.replace("!", "").replace("@", "").lower()
            op_arg = d.get("operator_argument") or ""
            lineno = d.get("oplineno", d.get("lineno", 1))

            if operator in _START_ANCHORED_OPERATORS:
                yield LintProblem(
                    line=lineno,
                    end_line=lineno,
                    desc=(
                        f"ARGS_NAMES targeted with @{operator} which does not handle the "
                        f"'json.' prefix added by libModSecurity3/Coraza to JSON parameter "
                        f"names. Replace with '@rx ^(?:json\\.)?...'; rule id: {current_ruleid}"
                    ),
                    rule="args_names_json_prefix",
                )
            elif operator == "rx" and _MISSING_JSON_PREFIX_RE.match(op_arg):
                yield LintProblem(
                    line=lineno,
                    end_line=lineno,
                    desc=(
                        f"ARGS_NAMES targeted with @rx pattern anchored to start ('^') but "
                        f"missing '(?:json\\.)?' prefix. libModSecurity3/Coraza prefixes JSON "
                        f"parameter names with 'json.', so '^foo' will not match 'json.foo'. "
                        f"Use '^(?:json\\.)?...' instead; rule id: {current_ruleid}"
                    ),
                    rule="args_names_json_prefix",
                )
