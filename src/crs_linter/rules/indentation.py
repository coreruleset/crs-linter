import difflib
import re
import msc_pyparser
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class Indentation(Rule):
    """Check for indentation errors in rules.

    This rule verifies that rule files follow CRS formatting guidelines for
    indentation and whitespace. The linter uses msc_pyparser to regenerate
    the formatted version of each file and compares it with the original
    using difflib to detect any formatting discrepancies.

    Example of failing rules (incorrect indentation):
         SecRule ARGS "@rx foo" \\  # Extra leading space
           "id:1,\\  # Wrong indentation (should be 4 spaces)
            phase:1,\\
            pass,\\
            nolog"

        SecRule ARGS "@rx foo" \\
             "id:3,\\  # Extra leading space
            phase:1,\\
            pass,\\
            nolog"

    Example of correct indentation:
        SecRule ARGS "@rx foo" \\
            "id:2,\\
            phase:1,\\
            pass,\\
            nolog"
    """

    def __init__(self):
        super().__init__()
        self.success_message = "Indentation check ok."
        self.error_message = "Indentation check found error(s)"
        self.error_title = "Indentation error"
        self.args = ("filename", "content", "file_content")

    def check(self, filename, content, file_content):
        """Check indentation in the file"""

        # Use the already-read file content (which has already been processed for .example files)
        if file_content is None:
            yield LintProblem(
                line=0,
                end_line=0,
                desc=f"File content not available for indentation check: {filename}",
                rule="indentation",
            )
            return

        original_content = file_content

        # Generate the formatted output from the parsed content
        writer = msc_pyparser.MSCWriter(content)
        writer.generate()
        formatted_output = "\n".join(writer.output)

        # Normalize trailing newlines: MSCWriter doesn't add a trailing newline,
        # but most editors do. We strip trailing newlines from both to compare content.
        original_normalized = original_content.rstrip('\n')
        formatted_normalized = formatted_output.rstrip('\n')

        # Compare line by line
        original_lines = original_normalized.splitlines(keepends=True)
        formatted_lines = formatted_normalized.splitlines(keepends=True)

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
                # Check if the removed and added lines are identical (indicating whitespace-only changes)
                if removed_lines == added_lines and removed_lines:
                    # This is a whitespace/trailing newline issue
                    desc = f"Indentation/whitespace error (lines {start_line}-{start_line + count - 1}): check spacing and formatting"
                else:
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
        