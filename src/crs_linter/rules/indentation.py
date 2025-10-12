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

        diff_lines = list(difflib.unified_diff(from_lines, output, lineterm=''))
        if from_lines == output:
            # No indentation errors
            return

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

    def _remove_comments(self, content):
        """Remove comments from content"""
        lines = content.split('\n')
        result = []
        for line in lines:
            if not line.strip().startswith('#'):
                result.append(line)
        return '\n'.join(result)
