from crs_linter.ignorecase import Coverage, lowercase_rx_rules
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class LowercaseIgnorecase(Rule):
    """Check for combined transformation and ignorecase patterns.

    This rule detects when rules use both the t:lowercase transformation and
    the (?i) case-insensitive regex flag together. This combination is
    redundant and should be avoided - use one or the other.

    Example of a failing rule (combining t:lowercase and (?i)):
        SecRule ARGS "@rx (?i)foo" \\
            "id:1,\\
            phase:1,\\
            pass,\\
            t:lowercase,\\  # Fails: redundant with (?i) flag
            nolog"

    The rule should use either:
    - t:lowercase with a case-sensitive regex: "@rx foo"
    - (?i) flag without t:lowercase transformation

    The check only fires when the flag covers the whole pattern, as in
    `^(?i)foo`, `(?si)foo` or a `(?i:...)` group spanning everything. A pattern
    with only part of it flagged, such as `(?i:foo)|bar`, still needs
    t:lowercase for the rest, and a rule whose lowercased value is read later
    (MATCHED_VAR, %{tx.0} in a setvar or a chained rule) needs t:lowercase
    itself, so neither is reported. The same goes for a transformation after
    t:lowercase that is not known to be harmless (a decoder such as
    t:base64Decode), and for a t:lowercase cancelled by a later t:none.
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No combined transformation and ignorecase patterns found."
        self.error_message = "Found combined transformation and ignorecase pattern(s)"
        self.error_title = "combined transformation and ignorecase"
        self.args = ("data",)

    def check(self, data):
        """check for combined transformation and ignorecase patterns"""
        for ruleid, lowered, coverage, reads, alters in lowercase_rx_rules(data):
            if coverage is not Coverage.FULL or reads or alters:
                continue
            for a in lowered:
                yield LintProblem(
                    line=a["lineno"],
                    end_line=a["lineno"],
                    desc=f'rule uses (?i) in combination with t:lowercase: \'{a["act_arg"]}\'; rule id: {ruleid}',
                    rule="lowercase_ignorecase",
                )
