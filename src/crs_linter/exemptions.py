"""
Exemption mechanism for CRS Linter.

This module provides functionality to parse and apply exemption comments in
ModSecurity configuration files. Exemption comments allow users to suppress
specific linting rules for individual rules.

Format: #crs-linter:ignore:rule1,rule2,rule3

The exemption comment applies to the next non-comment, non-blank line.
"""

import re
from typing import Dict, Set

# Regex pattern for exemption comments
# Format: #crs-linter:ignore:rule1,rule2,rule3
# Case-insensitive for keywords, whitespace tolerant
EXEMPTION_PATTERN = re.compile(
    r'^\s*#\s*crs-linter\s*:\s*ignore\s*:\s*([a-z_,\s]+)\s*$',
    re.IGNORECASE
)


def parse_exemptions(file_content: str) -> Dict[int, Set[str]]:
    """
    Parse exemption comments from file content.

    Args:
        file_content: Raw file content as string

    Returns:
        Dictionary mapping line ranges to sets of exempted rule names.
        The dictionary maps start line to (end_line, rule_names_set).

    Example:
        >>> content = '''
        ... #crs-linter:ignore:lowercase_ignorecase,deprecated
        ... SecRule ARGS "@rx foo" "id:1001"
        ... '''
        >>> exemptions = parse_exemptions(content)
        >>> exemptions[2]
        (2, {'lowercase_ignorecase', 'deprecated'})
    """
    exemptions = {}
    if not file_content:
        return exemptions

    lines = file_content.split('\n')

    for idx, line in enumerate(lines):
        match = EXEMPTION_PATTERN.match(line)
        if match:
            # Extract and parse rule names
            rule_names_str = match.group(1)
            rule_names = {
                name.strip().lower()
                for name in rule_names_str.split(',')
                if name.strip()
            }

            # Find the target line range (next non-comment, non-blank line and its end)
            start_line, end_line = find_next_rule_range(lines, idx)
            if start_line > 0:
                # Store exemption for the start line with range info
                if start_line in exemptions:
                    # Merge rule names and extend range if needed
                    existing_end, existing_rules = exemptions[start_line]
                    exemptions[start_line] = (
                        max(existing_end, end_line),
                        existing_rules | rule_names
                    )
                else:
                    exemptions[start_line] = (end_line, rule_names)

    return exemptions


def find_next_rule_line(lines: list, start_idx: int) -> int:
    """
    Find the next non-comment, non-blank line after start_idx.

    Args:
        lines: List of file lines
        start_idx: Starting index (0-based)

    Returns:
        Line number (1-based) of next rule line, or 0 if not found
    """
    for idx in range(start_idx + 1, len(lines)):
        line = lines[idx].strip()
        if line and not line.startswith('#'):
            return idx + 1  # Convert to 1-based line number
    return 0


def find_next_rule_range(lines: list, start_idx: int) -> tuple:
    """
    Find the line range of the next rule after start_idx.

    This function finds the start and end lines of a ModSecurity rule,
    accounting for multi-line rules with backslash continuation.

    Args:
        lines: List of file lines
        start_idx: Starting index (0-based)

    Returns:
        Tuple of (start_line, end_line) both 1-based, or (0, 0) if not found
    """
    # Find start line (first non-comment, non-blank line)
    start_line = find_next_rule_line(lines, start_idx)
    if start_line == 0:
        return (0, 0)

    start_idx = start_line - 1  # Convert back to 0-based

    # Find end line by looking for line continuation backslashes
    end_idx = start_idx
    for idx in range(start_idx, len(lines)):
        line = lines[idx].rstrip()
        end_idx = idx
        # If line doesn't end with backslash, this is the last line
        if not line.endswith('\\'):
            break

    return (start_line, end_idx + 1)  # Both 1-based


def should_exempt_problem(problem, exemptions: Dict[int, tuple]) -> bool:
    """
    Check if a lint problem should be exempted based on exemption comments.

    Args:
        problem: LintProblem object to check
        exemptions: Dictionary mapping start lines to (end_line, rule_names_set) tuples

    Returns:
        True if the problem should be suppressed, False otherwise
    """
    if not problem.rule:
        return False

    # Check if the problem line falls within any exempted range
    for start_line, (end_line, rule_names) in exemptions.items():
        if start_line <= problem.line <= end_line:
            if problem.rule in rule_names:
                return True

    return False
