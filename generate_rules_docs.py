#!/usr/bin/env python3
"""
Generate linting rules documentation from docstrings.

This script extracts docstrings from rule classes and generates a
"Linting Rules Reference" section for the README.md file.

Usage:
    python generate_rules_docs.py [--check]

Options:
    --check     Check if generated docs match current README (for CI)
"""

import sys
import inspect
import re
from pathlib import Path
from typing import List, Dict, Tuple


def extract_rule_docs() -> List[Dict[str, str]]:
    """
    Extract docstrings from all registered rule classes.

    Uses the Rules singleton to get all registered rules, ensuring the
    documentation reflects exactly the rules that the linter knows about.

    Returns:
        List of dicts with 'name', 'module_name', and 'docstring' keys,
        sorted by module name.
    """
    # Add src to path so we can import the modules
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    # Import linter to trigger all rule auto-registrations
    import crs_linter.linter  # noqa: F401
    from crs_linter.rules_metadata import get_registered_rules

    docs = []
    for rule in get_registered_rules():
        cls = rule.__class__
        module_name = cls.__module__.rsplit('.', 1)[-1]
        docstring = inspect.getdoc(cls)
        if docstring:
            docs.append({
                'name': cls.__name__,
                'module_name': module_name,
                'docstring': docstring
            })

    # Sort by module name for consistent ordering
    docs.sort(key=lambda d: d['module_name'])
    return docs


def format_code_blocks(docstring: str) -> str:
    """
    Format code blocks in docstrings with proper markdown triple backticks.

    Detects indented code blocks (especially ModSecurity rules) and wraps them
    in triple backticks for proper markdown rendering.

    Args:
        docstring: The original docstring text

    Returns:
        Formatted docstring with code blocks wrapped in backticks
    """
    lines = docstring.split('\n')
    result = []
    in_code_block = False
    code_block_lines = []

    # ModSecurity directives that indicate actual code
    code_directives = ['SecRule', 'SecAction', 'SecRuleUpdateTargetById', 'SecRuleRemoveById']
    
    # Number of lines to check ahead when detecting code blocks after Example headers
    LOOKAHEAD_LINES = 5

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if this line is the start of an example section
        if re.match(r'^\s*(Example|example).*:', line):
            # This is an example header, keep it as-is
            if in_code_block:
                # Close any previous code block
                result.extend(code_block_lines)
                result.append('```')
                code_block_lines = []
                in_code_block = False
            result.append(line)
            i += 1

            # Check if the next lines are indented (code) and contain non-whitespace content
            if i < len(lines) and lines[i].startswith('    ') and lines[i].strip():
                # Look ahead to see if there's actual code (not just descriptive text)
                has_code_ahead = False
                for lookahead_line in lines[i:i+LOOKAHEAD_LINES]:
                    if any(directive in lookahead_line for directive in code_directives):
                        has_code_ahead = True
                        break

                if has_code_ahead:
                    in_code_block = True
                    result.append('\n```apache')
            continue

        # Check if this is an indented line that contains ModSecurity directives
        is_code_line = False
        if line.startswith('    ') and line.strip():  # At least 4 spaces and not empty
            stripped = line.strip()
            # Check for actual code directives, comment lines, or continuation of code
            if any(directive in line for directive in code_directives):
                is_code_line = True
            elif stripped.startswith('#'):
                # Indented comment line; treat as part of code (can start a new block)
                is_code_line = True
            elif in_code_block and ('"' in line or '\\' in line):
                # Likely continuation of a rule within a code block
                is_code_line = True

        if is_code_line:
            if not in_code_block:
                # Start a new code block
                in_code_block = True
                result.append('\n```apache')
            # Add the line with reduced indentation (remove the 4-space docstring indent)
            code_block_lines.append(line[4:])
        else:
            # Not a code line
            if in_code_block:
                # Close the code block
                result.extend(code_block_lines)
                result.append('```\n')
                code_block_lines = []
                in_code_block = False

            # Add the regular line
            result.append(line)

        i += 1

    # Close any remaining code block
    if in_code_block:
        result.extend(code_block_lines)
        result.append('```')

    return '\n'.join(result)


def format_rule_docs(docs: List[Dict[str, str]]) -> str:
    """
    Format extracted docstrings into Markdown.

    Args:
        docs: List of rule documentation dicts

    Returns:
        Formatted Markdown string
    """


    lines = ["# 📖 Linting Rules Reference\n"]
    lines.append("This section is automatically generated from the Python docstrings in `src/crs_linter/rules/`.\n")
    lines.append("> 💡 **To update this documentation**: Edit the docstrings in the rule class files and run `python generate_rules_docs.py`.\n")

    for doc in docs:
        # Add rule name as heading
        lines.append(f"## {doc['name']}")
        lines.append("")

        # Add source file reference
        lines.append(f"**Source:** `src/crs_linter/rules/{doc['module_name']}.py`\n")

        # Add the docstring content with code blocks formatted
        formatted_docstring = format_code_blocks(doc['docstring'])
        lines.append(formatted_docstring)
        lines.append("")  # Extra blank line between rules

    return "\n".join(lines)


def find_markers(content: str) -> Tuple[int, int]:
    """
    Find the start and end positions of the generated docs markers.

    Args:
        content: README.md content

    Returns:
        Tuple of (start_pos, end_pos) or (-1, -1) if markers not found
    """
    start_marker = "<!-- GENERATED_RULES_DOCS_START -->"
    end_marker = "<!-- GENERATED_RULES_DOCS_END -->"

    start_pos = content.find(start_marker)
    end_pos = content.find(end_marker)

    if start_pos == -1 or end_pos == -1:
        return (-1, -1)

    # Return positions after start marker and before end marker
    return (start_pos + len(start_marker), end_pos)


def update_readme(generated_docs: str, check_only: bool = False) -> bool:
    """
    Update README.md with generated documentation.

    Args:
        generated_docs: The generated documentation string
        check_only: If True, only check if update is needed (don't modify file)

    Returns:
        True if README is up to date (or was updated), False if update needed
    """
    readme_path = Path(__file__).parent / "README.md"

    if not readme_path.exists():
        print(f"Error: {readme_path} not found", file=sys.stderr)
        return False

    # Read current README
    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find markers
    start_pos, end_pos = find_markers(content)

    if start_pos == -1:
        print("Error: Could not find markers in README.md", file=sys.stderr)
        print("Please add the following markers where you want the generated docs:", file=sys.stderr)
        print("  <!-- GENERATED_RULES_DOCS_START -->", file=sys.stderr)
        print("  <!-- GENERATED_RULES_DOCS_END -->", file=sys.stderr)
        return False

    # Extract current generated content
    current_generated = content[start_pos:end_pos].strip()
    new_generated = generated_docs.strip()

    if current_generated == new_generated:
        if check_only:
            print("✓ README.md is up to date")
        else:
            print("README.md is already up to date")
        return True

    if check_only:
        print("✗ README.md is out of date", file=sys.stderr)
        print("Run 'python generate_rules_docs.py' to update", file=sys.stderr)
        return False

    # Update content
    new_content = (
        content[:start_pos] +
        "\n" + new_generated + "\n" +
        content[end_pos:]
    )

    # Write updated README
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"✓ Updated {readme_path}")
    return True


def main():
    """Main entry point."""
    check_only = '--check' in sys.argv

    print("Extracting rule documentation from docstrings...")
    docs = extract_rule_docs()

    if not docs:
        print("Error: No rule documentation found", file=sys.stderr)
        return 1

    print(f"Found {len(docs)} rule classes")

    print("Generating Markdown documentation...")
    generated_docs = format_rule_docs(docs)

    print("Updating README.md...")
    success = update_readme(generated_docs, check_only)

    if not success:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
