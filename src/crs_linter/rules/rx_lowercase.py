from crs_linter.ignorecase import Coverage, lowercase_rx_rules
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class RxLowercase(Rule):
    """Check that @rx rules use the (?i) flag instead of t:lowercase.

    CRS matches case-insensitively with the (?i) regex flag (`##!+ i` in
    regex-assembly files). t:lowercase is kept for operators without a flag,
    such as @within, @streq or @contains. Unlike t:lowercase, (?i) keeps the
    original casing in MATCHED_VAR and logdata, and does not depend on the
    transformation pipeline.

    Example of a failing rule (t:lowercase with @rx):
        SecRule ARGS "@rx foo" \\
            "id:1,\\
            phase:1,\\
            pass,\\
            t:lowercase,\\  # Fails: use "@rx (?i)foo" instead
            nolog"

    Only rules where (?i) can replace t:lowercase without changing what the
    rule does are reported. These are left alone:
    - rules whose lowercased value is read later (MATCHED_VAR or %{tx.0} in a
      setvar or a chained rule), because t:lowercase normalises that value
      and (?i) would not (see rule 920450). Logging only (logdata) does not count
    - patterns with no letters, where t:lowercase can only matter for the value
    - rules with a transformation after t:lowercase that is not known to be
      harmless (t:urlDecode, t:jsDecode, t:md5, ...): decoders can bring upper
      case back, so (?i) would match more
    - a t:lowercase cancelled by a later t:none, which does nothing
    - patterns the flag parser does not understand (recursion, conditionals)
    - patterns already fully covered by (?i), which lowercase_ignorecase reports

    Only the transformations after the last t:none count.

    A pattern that is only partly flagged, such as `(?i:foo)bar`, is reported
    with a hint to put the whole pattern under (?i).

    Rules that still need t:lowercase for another reason are exempted with:
        #crs-linter:ignore:rx_lowercase

    This check is opt-in, so older CRS releases and plugins are not affected.
    Enable it in the config file passed with -c:
        enable_checks = ["rx_lowercase"]
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No @rx rule uses t:lowercase."
        self.error_message = "Found @rx rule(s) using t:lowercase"
        self.error_title = "t:lowercase with @rx"
        self.args = ("data",)
        self.opt_in = True

    def check(self, data):
        """check for t:lowercase on @rx rules"""
        for ruleid, lowered, coverage, reads, alters in lowercase_rx_rules(data):
            if reads or alters or coverage not in (Coverage.NONE, Coverage.PARTIAL):
                continue
            hint = (
                "part of the pattern is not covered by (?i), put the whole pattern under (?i)"
                if coverage is Coverage.PARTIAL
                else "use the (?i) flag instead"
            )
            for a in lowered:
                yield LintProblem(
                    line=a["lineno"],
                    end_line=a["lineno"],
                    desc=f"rule uses t:lowercase with @rx, {hint}; rule id: {ruleid}",
                    rule="rx_lowercase",
                )
