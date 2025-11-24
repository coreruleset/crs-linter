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
import importlib
import inspect
from pathlib import Path
from typing import List, Dict, Tuple


def extract_rule_docs() -> List[Dict[str, str]]:
    """
    Extract docstrings from all rule classes in src/crs_linter/rules/.

    Returns:
        List of dicts with 'name', 'module_name', and 'docstring' keys.
    """
    # Add src to path so we can import the modules
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    rules_dir = Path(__file__).parent / "src" / "crs_linter" / "rules"
    docs = []

    # Get all Python files in the rules directory
    rule_files = sorted(rules_dir.glob("*.py"))

    for rule_file in rule_files:
        if rule_file.name == "__init__.py":
            continue

        try:
            module_name = f"crs_linter.rules.{rule_file.stem}"
            module = importlib.import_module(module_name)

            # Find classes that inherit from Rule (have a 'check' method)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's defined in this module and has a check method
                if obj.__module__ == module_name and hasattr(obj, 'check'):
                    docstring = inspect.getdoc(obj)
                    if docstring:
                        docs.append({
                            'name': name,
                            'module_name': rule_file.stem,
                            'docstring': docstring
                        })
                    break  # Only one rule class per file
        except Exception as e:
            print(f"Warning: Could not import {rule_file.name}: {e}", file=sys.stderr)

    return docs


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

        # Add the docstring content
        lines.append(doc['docstring'])
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
