import difflib
import re
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
                if Path(filename).name.startswith("crs-setup.conf.example"):
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
        formatted_output = "\n".join(writer.output)
        
        # Compare line by line
        original_lines = original_content.splitlines(keepends=True)
        formatted_lines = formatted_output.splitlines(keepends=True)

        # Normalize line counts for comparison
        if len(original_lines) < len(formatted_lines):
            original_lines.append("\n")
        elif len(original_lines) > len(formatted_lines):
            formatted_lines.append("\n")

        # Check if they're identical
        if original_lines == formatted_lines:
            # No indentation errors
            return

        # Generate diff to show differences
        diff_lines = list(difflib.unified_diff(original_lines, formatted_lines, lineterm=''))
        
        # Process the diff to extract meaningful error messages
        i = 0
        while i < len(diff_lines):
            line = diff_lines[i]
            # Look for diff hunk headers like "@@ -1,2 +1,2 @@"
            r = re.match(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$", line)
            if r:
                start_line = int(r.group(1))
                count = int(r.group(2))
                
                # Collect the diff lines for this hunk to show context
                removed_lines = []
                added_lines = []
                j = i + 1
                while j < len(diff_lines) and not diff_lines[j].startswith('@@'):
                    diff_line = diff_lines[j]
                    if diff_line.startswith('-'):
                        # Line in original file that should be removed
                        content = diff_line[1:].strip()
                        if content:  # Only show non-empty content
                            removed_lines.append(content[:60])  # Limit line length
                    elif diff_line.startswith('+'):
                        # Line that should be added (expected format)
                        content = diff_line[1:].strip()
                        if content:  # Only show non-empty content
                            added_lines.append(content[:60])  # Limit line length
                    j += 1
                
                # Create a meaningful error message
                desc_parts = []
                if removed_lines:
                    desc_parts.append(f"Remove: {', '.join(removed_lines[:2])}")
                    if len(removed_lines) > 2:
                        desc_parts[-1] += f" (+{len(removed_lines) - 2} more)"
                if added_lines:
                    desc_parts.append(f"Expected: {', '.join(added_lines[:2])}")
                    if len(added_lines) > 2:
                        desc_parts[-1] += f" (+{len(added_lines) - 2} more)"
                
                if desc_parts:
                    desc = f"Indentation/formatting error - {' | '.join(desc_parts)}"
                else:
                    # Likely whitespace-only differences
                    desc = f"Indentation/whitespace error (lines {start_line}-{start_line + count - 1}): check spacing and formatting"
                
                yield LintProblem(
                    line=start_line,
                    end_line=start_line + count - 1,
                    desc=desc,
                    rule="indentation",
                )
                i = j
            else:
                i += 1
