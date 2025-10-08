from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class ApprovedTags(Rule):
    """Check that only tags from the util/APPROVED_TAGS file are used."""
    
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
            
        chained = False
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


