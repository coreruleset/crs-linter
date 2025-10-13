import difflib
from pathlib import Path
import msc_pyparser
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule
from crs_linter.utils import remove_comments


class Indentation(Rule):
    """Check for indentation errors in rules."""

    def __init__(self):
        super().__init__()
        self.success_message = "Indentation check ok."
        self.error_message = "Indentation check found error(s)"
        self.error_title = "Indentation error"
        self.args = ("filename", "content")

    def _compare_strings(self, str1, str2):
        # Create a SequenceMatcher object
        matcher = difflib.SequenceMatcher(None, str1, str2)
        
        # Get the differences
        differences = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != 'equal':
                differences.append((tag, str1[i1:i2], str2[j1:j2]))
        
        return differences

    def check(self, filename, content):
        """Check indentation in the file"""
        error = False
        problems = []

        # Read the original file for comparison
        try:
            with open(filename, "r") as fp:
                original_content = fp.read()
                # Apply the same transformation as in cli.py for crs-setup.conf.example
                # This removes leading # from commented-out SecRule/SecAction blocks
                if Path(filename).name.endswith(".example"):
                    original_content = remove_comments(original_content)
        except:
            yield LintProblem(
                line=0,
                end_line=0,
                desc=f"Can't open file for indentation check: {filename}",
                rule="indentation",
            )
            return

        # Generate the formatted output from the parsed content
        writer = msc_pyparser.MSCWriter(content)
        writer.generate()
        # Add a newline to the end of the formatted output
        formatted_output = "\n".join(writer.output) + "\n"
        # Compare line by line
        diffs = self._compare_strings(original_content, formatted_output)
        
        for diff in diffs:
            yield LintProblem(
                    filename=filename,
                    line=0,
                    end_line=0,
                    desc=f"Change Type: {diff[0]}\nOriginal: {diff[1]}\nFormatted: {diff[2]}\n",
                    rule="indentation",
                )
        