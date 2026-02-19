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

import ast
import sys
import re
from pathlib import Path
from typing import List, Dict, Tuple


def _find_name_override(class_node: ast.ClassDef) -> str | None:
    """
    Look for a self.name = "..." assignment in __init__ to detect
    rules that override the default name derived from the module.
    """
    for node in ast.walk(class_node):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
                and target.attr == "name"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return node.value.value
    return None


def extract_rule_docs() -> List[Dict[str, str]]:
    """
    Extract docstrings from rule classes using AST parsing.

    Parses each rule .py file with the ast module to find Rule subclasses
    and their docstrings, without importing any modules. This avoids
    requiring external dependencies (msc_pyparser, dulwich, etc.).

    Returns:
        List of dicts with 'name', 'module_name', 'rule_name', and
        'docstring' keys, sorted by module name.
    """
    rules_dir = Path(__file__).parent / "src" / "crs_linter" / "rules"

    docs = []
    for rule_file in sorted(rules_dir.glob("*.py")):
        if rule_file.name.startswith("__"):
            continue

        module_name = rule_file.stem
        tree = ast.parse(rule_file.read_text(encoding="utf-8"), filename=str(rule_file))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Check that the class inherits from Rule
            if not any(
                (isinstance(b, ast.Name) and b.id == "Rule")
                or (isinstance(b, ast.Attribute) and b.attr == "Rule")
                for b in node.bases
            ):
                continue

            docstring = ast.get_docstring(node)
            if docstring:
                # Use overridden name if present, otherwise module name
                rule_name = _find_name_override(node) or module_name
                docs.append({
                    "name": node.name,
                    "module_name": module_name,
                    "rule_name": rule_name,
                    "docstring": docstring,
                })

    # Sort by module name for consistent ordering
    docs.sort(key=lambda d: d["module_name"])
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


def find_markers(content: str, section: str) -> Tuple[int, int]:
    """
    Find the start and end positions of a generated docs section.

    Args:
        content: README.md content
        section: Section name (e.g., 'RULES_DOCS', 'EXEMPTIONS_DOCS')

    Returns:
        Tuple of (start_pos, end_pos) or (-1, -1) if markers not found
    """
    start_marker = f"<!-- GENERATED_{section}_START -->"
    end_marker = f"<!-- GENERATED_{section}_END -->"

    start_pos = content.find(start_marker)
    end_pos = content.find(end_marker)

    if start_pos == -1 or end_pos == -1:
        return (-1, -1)

    # Return positions after start marker and before end marker
    return (start_pos + len(start_marker), end_pos)


def update_section(content: str, section: str, generated: str) -> Tuple[str, bool]:
    """
    Update a single generated section in the README content.

    Args:
        content: Current README content
        section: Section name (e.g., 'RULES_DOCS', 'EXEMPTIONS_DOCS')
        generated: New generated content for this section

    Returns:
        Tuple of (updated_content, changed). changed is True if content was modified.
    """
    start_pos, end_pos = find_markers(content, section)

    if start_pos == -1:
        print(f"Error: Could not find {section} markers in README.md", file=sys.stderr)
        print(f"  <!-- GENERATED_{section}_START -->", file=sys.stderr)
        print(f"  <!-- GENERATED_{section}_END -->", file=sys.stderr)
        return (content, False)

    current = content[start_pos:end_pos].strip()
    new = generated.strip()

    if current == new:
        return (content, False)

    updated = content[:start_pos] + "\n" + new + "\n" + content[end_pos:]
    return (updated, True)


def update_readme(sections: Dict[str, str], check_only: bool = False) -> bool:
    """
    Update README.md with generated documentation for all sections.

    Args:
        sections: Dict mapping section names to generated content
        check_only: If True, only check if update is needed (don't modify file)

    Returns:
        True if README is up to date (or was updated), False if update needed
    """
    readme_path = Path(__file__).parent / "README.md"

    if not readme_path.exists():
        print(f"Error: {readme_path} not found", file=sys.stderr)
        return False

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    any_changed = False
    for section, generated in sections.items():
        content, changed = update_section(content, section, generated)
        if changed:
            any_changed = True

    if not any_changed:
        if check_only:
            print("✓ README.md is up to date")
        else:
            print("README.md is already up to date")
        return True

    if check_only:
        print("✗ README.md is out of date", file=sys.stderr)
        print("Run 'python generate_rules_docs.py' to update", file=sys.stderr)
        return False

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✓ Updated {readme_path}")
    return True


def format_exemption_rule_list(docs: List[Dict[str, str]]) -> str:
    """
    Generate a Markdown table of valid rule names for the exemptions section.

    Args:
        docs: List of rule documentation dicts (from extract_rule_docs)

    Returns:
        Formatted Markdown string with the list of valid rule names
    """
    lines = [
        "The following rule names can be used in exemption comments:\n",
        "| Rule name | Description |",
        "| --- | --- |",
    ]
    # Build table from docs, sorted by rule_name
    for doc in sorted(docs, key=lambda d: d["rule_name"]):
        lines.append(f"| `{doc['rule_name']}` | [{doc['name']}](#{doc['name'].lower()}) |")

    return "\n".join(lines)


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
    generated_rules = format_rule_docs(docs)
    generated_exemptions = format_exemption_rule_list(docs)

    print("Updating README.md...")
    success = update_readme({
        "RULES_DOCS": generated_rules,
        "EXEMPTIONS_DOCS": generated_exemptions,
    }, check_only)

    if not success:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
