import re
import os.path
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class CrsTag(Rule):
    """Check that every rule has a `tag:'OWASP_CRS'` action and a tag for its filename.

    This rule verifies that:
    1. Every rule has a tag with value 'OWASP_CRS'
    2. Every non-administrative rule has a tag with value 'OWASP_CRS/$filename$'

    Example of a failing rule (missing OWASP_CRS tag):
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:attack-xss"  # Fails: missing tag:OWASP_CRS

    Example of a passing rule:
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:OWASP_CRS,\\
            tag:OWASP_CRS/test11"

    Files can be excluded from filename tag checking using the -f flag with
    a list of excluded files (see FILENAME_EXCLUSIONS for an example).
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No rule without required tags."
        self.error_message = "There are one or more rules without required tags"
        self.error_title = "Required tag is missing"
        self.args = ("data", "filename", "filename_tag_exclusions")
        # Regex to extract filename for tag generation
        self.re_fname = re.compile(r"(REQUEST|RESPONSE)\-\d{3}\-")

    def _gen_crs_file_tag(self, filename):
        """Generate expected tag from filename (e.g., OWASP_CRS/SQL-INJECTION)"""
        fname = self.re_fname.sub("", os.path.basename(os.path.splitext(filename)[0]))
        fname = fname.replace("APPLICATION-", "")
        return "/".join(["OWASP_CRS", fname])

    def check(self, data, filename=None, filename_tag_exclusions=None):
        """
        Check that every rule has a `tag:'OWASP_CRS'` action and a tag for its filename
        """
        if filename_tag_exclusions is None:
            filename_tag_exclusions = []

        # Generate expected filename tag
        expected_filename_tag = None
        check_filename_tag = False
        if filename:
            expected_filename_tag = self._gen_crs_file_tag(filename)
            # Check if this file should be excluded from filename tag checking
            check_filename_tag = os.path.basename(filename) not in filename_tag_exclusions

        chained = False
        ruleid = 0
        has_crs = False
        has_filename_tag = False
        tags_in_rule = []

        for d in data:
            if "actions" in d:
                chainlevel = 0

                if not chained:
                    ruleid = 0
                    has_crs = False
                    has_filename_tag = False
                    tags_in_rule = []
                    chainlevel = 0
                else:
                    chained = False

                for a in d["actions"]:
                    if a["act_name"] == "id":
                        ruleid = int(a["act_arg"])
                    if a["act_name"] == "chain":
                        chained = True
                        chainlevel += 1
                    if a["act_name"] == "tag":
                        if chainlevel == 0:
                            tag_value = a["act_arg"]
                            tags_in_rule.append(tag_value)
                            if tag_value == "OWASP_CRS":
                                has_crs = True
                            if expected_filename_tag and tag_value == expected_filename_tag:
                                has_filename_tag = True

                # Skip CRS admin rules (rule IDs ending in 1-9)
                if ruleid > 0 and ruleid % 10 in range(1, 10):
                    continue

                # Check for missing OWASP_CRS tag
                if ruleid > 0 and not has_crs:
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule does not have tag with value 'OWASP_CRS'; rule id: {ruleid}",
                        rule="crs_tag",
                    )

                # Check for missing filename tag (if applicable)
                if ruleid > 0 and check_filename_tag and expected_filename_tag and not has_filename_tag:
                    yield LintProblem(
                        line=a["lineno"],
                        end_line=a["lineno"],
                        desc=f"rule does not have tag for filename: expected '{expected_filename_tag}'; rule id: {ruleid}",
                        rule="crs_tag",
                    )


