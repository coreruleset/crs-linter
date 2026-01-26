import re
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CollectionCaptureChain(Rule):
    """Check for CVE-2026-21876 vulnerability pattern: capturing from collection variables with chained validation.

    This rule detects a dangerous pattern where:
    1. A rule captures from a collection variable (like MULTIPART_PART_HEADERS, REQUEST_HEADERS, ARGS, etc.)
    2. Uses the `capture` action
    3. Has a chained rule that validates the captured TX variable (TX:0, TX:1, etc.)

    This pattern is vulnerable because ModSecurity iterates through all items in the collection,
    overwriting the capture variable (TX:0, TX:1, etc.) on each iteration. The chained rule
    executes once after all iterations complete, so it only validates the LAST captured value.

    Example of vulnerable pattern (CVE-2026-21876):

        SecRule MULTIPART_PART_HEADERS "@rx ^content-type\\s*:\\s*(.*)$" \\
            "id:922110,\\
            phase:2,\\
            block,\\
            capture,\\
            t:none,\\
            msg:'Multipart request with invalid charset',\\
            chain"
            SecRule TX:1 "@rx ^(?:charset\\s*=\\s*['\"]?(?!utf-8|iso-8859-1|iso-8859-15|windows-1252)[^'\";]+)"

    In this example, if there are multiple MULTIPART_PART_HEADERS, only the last one's
    charset will be validated. An attacker can place a malicious charset (e.g., UTF-7)
    in an early part and a legitimate charset (UTF-8) in the last part to bypass detection.

    Fix approaches:
    1. Use a single-pass validation without chains
    2. Validate within the same rule using a combined pattern
    3. Use setvar to accumulate values and validate the full set

    For more information, see:
    https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/
    """
    def __init__(self):
        super().__init__()
        self.name = "collection_capture_chain"
        self.success_message = "No rules capture from collection variables with chained TX.N validation."
        self.error_message = "Found rules that capture from collection variables with chained TX.N validation (CVE-2026-21876 pattern)."
        self.error_title = "Dangerous collection capture with chained validation"
        self.args = ("data",)

        # Collection variables that can have multiple values
        # These are ModSecurity variables that iterate over collections
        self.collection_variables = {
            'args', 'args_names', 'args_get', 'args_get_names',
            'args_post', 'args_post_names', 'args_combined_size',
            'request_headers', 'request_headers_names',
            'request_cookies', 'request_cookies_names',
            'response_headers', 'response_headers_names',
            'multipart_part_headers',
            'files', 'files_names', 'files_sizes',
            'files_tmpnames', 'files_tmp_content',
            'matched_vars', 'matched_vars_names',
            'geo', 'tx'  # These can also be collections in some contexts
        }

        # Pattern to detect TX.N references (TX:0, TX:1, etc.)
        self.tx_pattern = re.compile(r"^\d$")

    def check(self, data):
        """
        Check for the CVE-2026-21876 vulnerability pattern.

        Detects rules that:
        1. Operate on a collection variable
        2. Have a capture action
        3. Have a chained rule that references TX:N (captured values)
        """
        chained = False
        ruleid = 0
        has_capture = False
        uses_collection = False
        collection_var_name = None
        rule_line = 0

        for d in data:
            # Only check SecRule directives
            if d["type"].lower() != "secrule":
                continue

            # If this is a chained rule (continuation of previous rule)
            if chained:
                # Check if this chained rule references TX.N (captured values)
                if uses_collection and has_capture:
                    for v in d["variables"]:
                        if (v["variable"].lower() == "tx" and
                            v.get("variable_part") and
                            self.tx_pattern.match(v["variable_part"])):
                            # Found the vulnerable pattern!
                            yield LintProblem(
                                line=rule_line,
                                end_line=rule_line,
                                desc=(
                                    f"rule {ruleid} captures from collection variable {collection_var_name} "
                                    f"and validates TX:{v['variable_part']} in chained rule. "
                                    "This only validates the LAST item in the collection. "
                                    "See CVE-2026-21876."
                                ),
                                rule="collection_capture_chain",
                            )
                            # Only report once per rule chain
                            break

            # Process this rule's actions
            if "actions" in d:
                # If not in a chain, this is the start of a new rule/chain
                if not chained:
                    # Reset state for new rule
                    uses_collection = False
                    collection_var_name = None
                    has_capture = False
                    ruleid = 0

                    # Check if this rule uses a collection variable
                    for v in d["variables"]:
                        var_name = v["variable"].lower()
                        if var_name in self.collection_variables:
                            uses_collection = True
                            collection_var_name = var_name.upper()
                            rule_line = v.get("lineno", 0)

                # Now reset chained flag and check for chain action
                chained = False

                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "capture":
                        has_capture = True
                    if a["act_name"] == "chain":
                        chained = True

                # If no chain action at end of this rule, reset state
                if not chained:
                    uses_collection = False
                    collection_var_name = None
                    has_capture = False
                    ruleid = 0
