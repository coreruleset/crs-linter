import difflib
import re
from pathlib import Path
import msc_pyparser
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class Indentation(Rule):
    """Check for indentation errors in rules."""

    def __init__(self):
        super().__init__()
        self.success_message = "Indentation check ok."
        self.error_message = "Indentation check found error(s)"
        self.error_title = "Indentation error"
        self.args = ("filename", "content")

    def check(self, filename, content):
        """Check indentation in the file"""
        error = False
        problems = []

        # make a diff to check the indentations
        try:
            with open(filename, "r") as fp:
                from_lines = fp.readlines()
                if Path(filename).name.startswith("crs-setup.conf.example"):
                    from_lines = self._remove_comments("".join(from_lines)).split("\n")
                    from_lines = [l + "\n" for l in from_lines]
        except:
            yield LintProblem(
                line=0,
                end_line=0,
                desc=f"Can't open file for indentation check: {filename}",
                rule="indentation",
            )
            return

        # virtual output
        writer = msc_pyparser.MSCWriter(content)
        writer.generate()
        output = []
        for l in writer.output:
            output += [l + "\n" for l in l.split("\n") if l != "\n"]

        if len(from_lines) < len(output):
            from_lines.append("\n")
        elif len(from_lines) > len(output):
            output.append("\n")

        diff = difflib.unified_diff(from_lines, output)
        if from_lines == output:
            # No indentation errors
            return
        else:
            error = True

        for d in diff:
            d = d.strip("\n")
            r = re.match(r"^@@ -(\d+),(\d+) \+\d+,\d+ @@$", d)
            if r:
                line1, line2 = [int(i) for i in r.groups()]
                yield LintProblem(
                    line=line1,
                    end_line=line1 + line2,
                    desc="an indentation error was found",
                    rule="indentation",
                )

    def _remove_comments(self, content):
        """Remove comments from content"""
        lines = content.split('\n')
        result = []
        for line in lines:
            if not line.strip().startswith('#'):
                result.append(line)
        return '\n'.join(result)
