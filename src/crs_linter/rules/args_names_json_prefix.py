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

# A branch that opens with a negated character class immediately followed by a
# "zero-or-more"/"one-or-more" quantifier, e.g. "[^'"]*" or "[^!&()]+".
_LEADING_NEGATED_CLASS_RE = re.compile(r"^\[\^((?:\\.|[^\]])*)\][*+]")

# Characters that appear literally in the "json." prefix. If a leading negated
# character class excludes none of these, it will happily consume "json." as
# part of its match, so the anchor still succeeds against JSON-prefixed names.
_JSON_PREFIX_CHARS = frozenset("json.")


def _split_top_level_alternatives(pattern):
    """Split `pattern` on '|' that are not nested inside a group or char class."""
    branches = []
    start = 0
    depth = 0
    in_class = False
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            branches.append(pattern[start:i])
            start = i + 1
        i += 1
    branches.append(pattern[start:])
    return branches


def _leading_group_body(pattern):
    """If `pattern` starts with a non-capturing group, return its inner content."""
    if not pattern.startswith("(?:"):
        return None
    depth = 1
    in_class = False
    i = 3
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return pattern[3:i]
        i += 1
    return None


def _branch_absorbs_json_prefix(branch):
    """True if `branch` starts with a negated class that cannot exclude 'json.'."""
    m = _LEADING_NEGATED_CLASS_RE.match(branch)
    if not m:
        return False
    excluded = set(re.sub(r"\\(.)", r"\1", m.group(1)))
    return not (excluded & _JSON_PREFIX_CHARS)


def _tolerates_json_prefix(op_arg):
    """True if the ^-anchored pattern still matches values with a 'json.' prefix.

    Some CRS patterns anchor to the start of the value but lead with a negated
    character class (e.g. "^[^!&()]*)" or "^(?:[^']*'|[^"]*")"). Since none of
    the excluded characters appear in the literal "json." prefix, that leading
    class simply consumes the prefix as part of its match, so the rule keeps
    matching JSON-prefixed parameter names even without an explicit
    "(?:json\\.)?" — only one alternative needs to tolerate it, since the
    others still fire whenever this one doesn't.
    """
    remainder = op_arg[1:]  # strip leading '^'
    group_body = _leading_group_body(remainder)
    branches = _split_top_level_alternatives(group_body) if group_body is not None else [remainder]
    return any(_branch_absorbs_json_prefix(branch) for branch in branches)


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

            operator_display = operator_raw.replace("!", "").replace("@", "")
            operator = operator_display.lower()
            op_arg = d.get("operator_argument") or ""
            lineno = d.get("oplineno", d.get("lineno", 1))

            if operator in _START_ANCHORED_OPERATORS:
                yield LintProblem(
                    line=lineno,
                    end_line=lineno,
                    desc=(
                        f"ARGS_NAMES targeted with @{operator_display} which does not handle the "
                        f"'json.' prefix added by libModSecurity3/Coraza to JSON parameter "
                        f"names. Replace with '@rx ^(?:json\\.)?...'; rule id: {current_ruleid}"
                    ),
                    rule="args_names_json_prefix",
                )
            elif (
                operator == "rx"
                and _MISSING_JSON_PREFIX_RE.match(op_arg)
                and not _tolerates_json_prefix(op_arg)
            ):
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
