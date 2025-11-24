from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class ApprovedTags(Rule):
    """Check that only tags from the util/APPROVED_TAGS file are used.

    This rule verifies that all tags used in rules are registered in the
    util/APPROVED_TAGS file. Any tag not listed in this file will be
    considered a check failure.

    Example of a failing rule:
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:attack-xss,\\
            tag:my-custom-tag"  # Fails if 'my-custom-tag' not in APPROVED_TAGS

    To use a new tag on a rule, it must first be registered in the
    util/APPROVED_TAGS file.
    """

    def __init__(self):
        super().__init__()
        self.success_message = "No new tags added."
        self.error_message = "There are one or more new tag(s)."
        self.error_title = "new unlisted tag"
        self.args = ("data", "tags")

    def check(self, data, tags):
        """
        check that only tags from the util/APPROVED_TAGS file are used
        """
        # Skip if no tags list provided
        if tags is None:
            return

        ruleid = 0
        for d in data:
            if "actions" in d:
                for a in d["actions"]:
                   if a["act_name"] == "tag":
                        tag = a["act_arg"]
                        # check wheter tag is in tagslist
                        if tags.count(tag) == 0:
                            yield LintProblem(
                                    line=a["lineno"],
                                    end_line=a["lineno"],
                                    desc=f'rule uses unknown tag: "{tag}"; only tags registered in the util/APPROVED_TAGS file may be used; rule id: {ruleid}',
                                    rule="approved_tags"
                                )


