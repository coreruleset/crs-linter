"""
Exemption mechanism for CRS Linter.

This module provides functionality to parse and apply exemption comments in
ModSecurity configuration files. Exemption comments allow users to suppress
specific linting rules for individual rules.

Format: #crs-linter:ignore:rule1,rule2,rule3

The exemption comment applies to the next non-comment, non-blank line.
"""

import re
from typing import Dict, Set, Optional

# Regex pattern for exemption comments
# Format: #crs-linter:ignore:rule1,rule2,rule3
# Case-insensitive for keywords, whitespace tolerant
EXEMPTION_PATTERN = re.compile(
    r'^\s*#\s*crs-linter\s*:\s*ignore\s*:\s*([a-z_,\s]+)\s*$',
    re.IGNORECASE
)


def parse_exemptions(file_content: Optional[str]) -> Dict[int, tuple[int, Set[str]]]:
    """
    Parse exemption comments from file content.

    Args:
        file_content: Raw file content as string, or None

    Returns:
        Dictionary mapping start line numbers to tuples of (end_line, rule_names_set).
        Each entry represents an exemption range with the set of exempted rule names.

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
    accounting for multi-line rules with backslash continuation and
    chained rules (rules with 'chain' action).

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
        # If line doesn't end with backslash, this is the last line of this part
        if not line.endswith('\\'):
            break

    # Check if this rule has a 'chain' action
    # If so, extend the range to include chained rules
    if has_chain_action(lines, start_idx, end_idx):
        # Find the next chained rule (indented SecRule after current rule)
        chained_start = find_next_chained_rule(lines, end_idx)
        if chained_start > 0:
            # Recursively find the end of the chained rule
            # (it might also have chain action)
            # We need to pass the index BEFORE chained_start to find_next_rule_range
            # because that function looks for the NEXT rule after start_idx.
            # chained_start is 1-based line number, so:
            #   - chained_start - 1 converts to 0-based index of that line
            #   - chained_start - 2 is the index of the line before (where we start searching from)
            # We use max(0, ...) to ensure we don't get negative indices.
            search_start_idx = max(0, chained_start - 2)
            _, chained_end = find_next_rule_range(lines, search_start_idx)
            if chained_end > 0:
                end_idx = chained_end - 1  # Convert to 0-based

    return (start_line, end_idx + 1)  # Both 1-based


def has_chain_action(lines: list, start_idx: int, end_idx: int) -> bool:
    """
    Check if a rule has a 'chain' action.

    Args:
        lines: List of file lines
        start_idx: Starting index (0-based) of the rule
        end_idx: Ending index (0-based) of the rule

    Returns:
        True if the rule contains a 'chain' action, False otherwise
    """
    # Combine all lines of the rule
    rule_text = ' '.join(lines[start_idx:end_idx + 1])
    
    # Pattern to detect chain action within ModSecurity action strings
    # The character class [,"\s] matches comma, quote, or whitespace
    # This works for all cases:
    # - "chain,other" - matches because " precedes chain
    # - "other,chain" - matches because , precedes chain
    # - "chain" - matches because " precedes chain
    # - " chain" - matches because space precedes chain
    # The (?:[,"\s]|$) matches comma, quote, space, or end of string after chain
    chain_pattern = re.compile(r'[,"\s]chain(?:[,"\s]|$)', re.IGNORECASE)
    return bool(chain_pattern.search(rule_text))


def find_next_chained_rule(lines: list, after_idx: int) -> int:
    """
    Find the next chained SecRule after the given index.

    Chained rules are typically indented and immediately follow the parent rule.

    Args:
        lines: List of file lines
        after_idx: Index to start searching after (0-based)

    Returns:
        Line number (1-based) of the chained rule, or 0 if not found
    """
    for idx in range(after_idx + 1, len(lines)):
        line = lines[idx].strip()
        # Skip blank lines
        if not line:
            continue
        # Skip comments
        if line.startswith('#'):
            continue
        # Check if this is a SecRule (chained rules are also SecRule directives)
        if line.startswith('SecRule'):
            return idx + 1  # Convert to 1-based
        # If we hit a non-comment, non-blank, non-SecRule line, stop
        # (this means we've moved past any potential chained rule)
        break
    return 0


def validate_exemption_names(
    exemptions: Dict[int, tuple[int, Set[str]]],
    valid_names: Set[str],
) -> list[str]:
    """
    Validate that exemption rule names are valid registered rule names.

    Args:
        exemptions: Dictionary mapping start lines to (end_line, rule_names_set) tuples
        valid_names: Set of valid rule names from the Rules singleton

    Returns:
        List of warning messages for unknown rule names
    """
    warnings = []
    for start_line, (_, rule_names) in exemptions.items():
        for name in sorted(rule_names):
            if name not in valid_names:
                warnings.append(
                    f"line {start_line}: unknown exemption rule name '{name}'; "
                    f"valid names are: {', '.join(sorted(valid_names))}"
                )
    return warnings


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
    # No early breaking since exemptions dict is not guaranteed to be sorted
    for start_line, (end_line, rule_names) in exemptions.items():
        if start_line <= problem.line <= end_line:
            if problem.rule in rule_names:
                return True

    return False
