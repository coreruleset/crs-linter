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

    Important: Accessing a SINGLE specific collection key (e.g., REQUEST_HEADERS:Referer) is SAFE
    because no iteration occurs. However, multiple keys (e.g., REQUEST_HEADERS:Referer|REQUEST_HEADERS:Cookie)
    ARE vulnerable because ModSecurity iterates over them.

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

    Safe patterns (no iteration, no false positives):

        # Single specific key - only matches one value
        SecRule REQUEST_HEADERS:Referer "@rx (test)" \\
            "id:1,capture,chain"
            SecRule TX:1 "@rx evil"

    Vulnerable patterns (iteration occurs):

        # Multiple specific keys - iterates over both
        SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:Cookie "@rx (test)" \\
            "id:2,capture,chain"
            SecRule TX:1 "@rx evil"

        # No specific key - iterates over all headers
        SecRule REQUEST_HEADERS "@rx (test)" \\
            "id:3,capture,chain"
            SecRule TX:1 "@rx evil"

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

            # Check if this rule references TX.N (captured values)
            # This must come after we've updated state from previous rules in the chain
            if chained and uses_collection and has_capture:
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

                # Check if this rule uses a collection variable (check for ALL rules, not just first)
                # Collection iteration happens when:
                # 1. Collection without specific key (e.g., REQUEST_HEADERS)
                # 2. Multiple variables from same collection (e.g., REQUEST_HEADERS:Referer|REQUEST_HEADERS:Cookie)
                # Single variable with specific key is safe (e.g., REQUEST_HEADERS:Referer)
                collection_vars = {}
                for v in d["variables"]:
                    var_name = v["variable"].lower()
                    if var_name in self.collection_variables:
                        var_part = v.get("variable_part", "")
                        if var_name not in collection_vars:
                            collection_vars[var_name] = []
                        collection_vars[var_name].append(var_part)

                # Check if any collection is vulnerable to iteration
                if collection_vars:
                    # Reset uses_collection for this rule (will be set to True if vulnerable)
                    uses_collection = False
                    collection_var_name = None

                    for var_name, var_parts in collection_vars.items():
                        # Vulnerable if: no specific key OR multiple keys
                        if not var_parts[0] or len(var_parts) > 1:
                            uses_collection = True
                            collection_var_name = var_name.upper()
                            # Add info about multiple keys if applicable
                            if len(var_parts) > 1 and var_parts[0]:
                                collection_var_name = f"{collection_var_name}:{var_parts[0]}|..."
                            rule_line = d["variables"][0].get("lineno", 0)
                            break
                else:
                    # No collection variables in this rule - if chained, this overwrites any previous capture
                    if chained:
                        uses_collection = False
                        collection_var_name = None

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
