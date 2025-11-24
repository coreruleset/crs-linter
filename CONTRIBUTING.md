# Contributing to CRS Linter

Thank you for your interest in contributing to CRS Linter! This guide will help you add new linting rules to the project.

## Table of Contents

- [Overview](#overview)
- [Adding a New Linting Rule](#adding-a-new-linting-rule)
- [Writing Tests](#writing-tests)
- [Adding Documentation](#adding-documentation)
- [Running Tests](#running-tests)
- [Code Style Guidelines](#code-style-guidelines)

---

## Overview

CRS Linter is a tool for validating OWASP CRS configuration files. Each linting rule is implemented as a separate Python class that inherits from the base `Rule` class.

The project structure:
```
crs-linter/
├── src/crs_linter/
│   ├── rules/           # All linting rules
│   ├── rule.py          # Base Rule class
│   └── lint_problem.py  # LintProblem class for reporting issues
├── tests/               # Test files
├── examples/            # Example config files for testing
└── generate_rules_docs.py  # Documentation generator script
```

---

## Adding a New Linting Rule

### Step 1: Create a New Rule File

Create a new Python file in `src/crs_linter/rules/` with a descriptive name (e.g., `my_check.py`).

### Step 2: Implement the Rule Class

Your rule class must:
1. Inherit from the `Rule` base class
2. Include a comprehensive docstring (this becomes the documentation)
3. Implement the `check()` method
4. Yield `LintProblem` objects when issues are found

**Template:**

```python
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class MyCheck(Rule):
    """Brief description of what this rule checks.

    Detailed explanation of the rule's purpose, what it validates,
    and why it's important for CRS rule files.

    Example of a failing rule (description of what's wrong):
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog"  # Add comment explaining why this fails

    Example of a passing rule (description of what's correct):
        SecRule REQUEST_URI "@rx index.php" \\
            "id:2,\\
            phase:1,\\
            deny,\\
            t:none,\\
            nolog,\\
            tag:OWASP_CRS"  # Add comment explaining why this passes

    Additional context, edge cases, or references to CRS documentation
    can be included here.
    """

    def __init__(self):
        super().__init__()
        # Customize these messages for your rule
        self.success_message = "My check passed."
        self.error_message = "My check found error(s)"
        self.error_title = "My Check Error"

        # Specify what arguments your check() method needs
        # Common arguments: "data", "filename", "content", "tags", etc.
        self.args = ("data",)

        # Optional: Add kwargs if needed
        self.kwargs = {}

        # Optional: Add a condition function if this rule should only
        # run under certain circumstances
        self.condition_func = None

    def check(self, data):
        """
        Perform the actual linting check.

        Args:
            data: Parsed rule data structure (list of dicts)
                  Each dict represents a SecRule/SecAction/etc.
                  Common keys: "type", "variables", "operator", "actions", "lineno"

        Yields:
            LintProblem: For each issue found
        """
        for rule in data:
            # Skip non-SecRule items if needed
            if rule["type"].lower() != "secrule":
                continue

            # Extract rule ID for error messages
            rule_id = 0
            if "actions" in rule:
                for action in rule["actions"]:
                    if action["act_name"] == "id":
                        rule_id = int(action["act_arg"])
                        break

            # Implement your check logic here
            # Example: Check if rule has a specific action
            has_required_action = False
            if "actions" in rule:
                for action in rule["actions"]:
                    if action["act_name"] == "my_required_action":
                        has_required_action = True
                        break

            # Yield a LintProblem if the check fails
            if not has_required_action:
                yield LintProblem(
                    line=rule.get("lineno", 0),
                    end_line=rule.get("lineno", 0),
                    desc=f"Rule is missing required action 'my_required_action'; rule id: {rule_id}",
                    rule="mycheck"  # Use lowercase, underscores for rule identifier
                )
```

### Step 3: Understanding Common Arguments

Your `check()` method can request different arguments by setting `self.args`:

| Argument | Type | Description |
|----------|------|-------------|
| `data` | `list[dict]` | Parsed rule structures from msc_pyparser |
| `filename` | `str` | Path to the file being checked |
| `content` | `msc_pyparser.MSCParser` | Parsed content object |
| `file_content` | `str` | Raw file content as string |
| `tags` | `list[str]` | List of approved tags (if `-t` flag provided) |
| `crsversion` | `str` | CRS version string (if provided) |

### Step 4: Working with Parsed Data Structure

The `data` argument is a list of parsed ModSecurity directives. Each item is a dictionary with the following common structure:

```python
{
    "type": "SecRule",           # Directive type: SecRule, SecAction, SecMarker, etc.
    "lineno": 42,                # Line number in source file
    "variables": [               # List of variables (targets)
        {
            "variable": "ARGS",
            "variable_part": "id",
            "quoted": "quoted",
            "negated": False,
            "counter": False
        }
    ],
    "operator": {
        "operator": "@rx",
        "operator_argument": "pattern",
        "negated": False
    },
    "actions": [                 # List of actions
        {
            "act_name": "id",
            "act_arg": "920100",
            "lineno": 42
        },
        {
            "act_name": "phase",
            "act_arg": "1",
            "lineno": 43
        }
    ]
}
```

### Step 5: Auto-Registration

Your rule will be **automatically registered** when the module is imported, thanks to the `RuleMeta` metaclass. No manual registration is needed!

---

## Writing Tests

### Step 1: Create a Test File

Create a test file in `tests/` directory (e.g., `tests/test_my_check.py`).

### Step 2: Write Test Cases

Use pytest and follow this pattern:

```python
import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_my_check_passes():
    """Test that valid rules pass the check."""

    # Create a rule that should pass your check
    valid_rule = (
        'SecRule REQUEST_URI "@rx index.php" \\\n'
        '    "id:1,\\\n'
        '    phase:1,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    nolog,\\\n'
        '    my_required_action"'  # This makes the rule pass
    )

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        # Parse the content
        parsed = parse_config(valid_rule)
        assert parsed is not None

        # Run the linter
        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        # Check that your rule didn't report any problems
        my_check_problems = [p for p in problems if p.rule == "mycheck"]
        assert len(my_check_problems) == 0, \
            f"Expected no problems, but found: {my_check_problems}"
    finally:
        # Clean up
        os.unlink(temp_file)


def test_my_check_fails():
    """Test that invalid rules are caught by the check."""

    # Create a rule that should fail your check
    invalid_rule = (
        'SecRule REQUEST_URI "@rx index.php" \\\n'
        '    "id:1,\\\n'
        '    phase:1,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    nolog"'  # Missing my_required_action
    )

    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        # Parse the content
        parsed = parse_config(invalid_rule)
        assert parsed is not None

        # Run the linter
        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        # Check that your rule reported the problem
        my_check_problems = [p for p in problems if p.rule == "mycheck"]
        assert len(my_check_problems) > 0, \
            "Expected problems to be detected"

        # Verify the error message
        assert "my_required_action" in my_check_problems[0].desc, \
            f"Expected error message to mention missing action, got: {my_check_problems[0].desc}"
    finally:
        # Clean up
        os.unlink(temp_file)
```

### Step 3: Test Edge Cases

Make sure to test:
- Valid rules that should pass
- Invalid rules that should fail
- Edge cases (empty files, chained rules, etc.)
- Different rule types (SecRule, SecAction, etc.)

---

## Adding Documentation

Documentation is automatically generated from your rule's **class docstring**.

### Documentation Guidelines

1. **First line**: Brief one-sentence description
2. **Detailed explanation**: What the rule checks and why it matters
3. **Examples**: Include both failing and passing rule examples
4. **Additional context**: References to CRS documentation, related PRs, etc.

### Docstring Format

Use this format for consistency:

```python
class MyCheck(Rule):
    """Brief description of what this rule checks.

    Detailed explanation paragraph. Explain what the rule validates,
    why it's important, and any relevant context about CRS standards
    or ModSecurity behavior.

    Example of a failing rule (explain what's wrong):
        SecRule REQUEST_URI "@rx index.php" \\
            "id:1,\\
            phase:1,\\
            deny"  # Comment explaining the failure

    Example of a passing rule (explain what's correct):
        SecRule REQUEST_URI "@rx index.php" \\
            "id:2,\\
            phase:1,\\
            deny,\\
            my_required_action"  # Comment explaining why this passes

    Additional notes, references, or warnings can go here.
    See CRS PR #1234 or issue #5678 for more context.
    """
```

### Generating Documentation

After writing your docstring, generate the documentation:

```bash
# Generate and update README.md
python generate_rules_docs.py

# Or with uv:
uv run python generate_rules_docs.py

# Check if README is up to date (useful for CI):
python generate_rules_docs.py --check
```

This will:
1. Extract docstrings from all rule classes in `src/crs_linter/rules/`
2. Generate Markdown documentation
3. Update the section in `README.md` between the markers:
   - `<!-- GENERATED_RULES_DOCS_START -->`
   - `<!-- GENERATED_RULES_DOCS_END -->`

**Important**: Always run this script before committing your changes!

---

## Running Tests

### Run All Tests

```bash
# Using uv (recommended):
uv run pytest

# Or with pytest directly:
pytest
```

### Run Specific Test File

```bash
uv run pytest tests/test_my_check.py
```

### Run Specific Test Function

```bash
uv run pytest tests/test_my_check.py::test_my_check_passes
```

### Run with Verbose Output

```bash
uv run pytest -v
```

### Run with Coverage

```bash
uv run pytest --cov=crs_linter
```

---

## Code Style Guidelines

### General Rules

1. **Follow PEP 8**: Use 4 spaces for indentation, not tabs
2. **Descriptive names**: Use clear, descriptive class and method names
3. **Type hints**: Add type hints where appropriate (optional but encouraged)
4. **Comments**: Explain complex logic with inline comments

### Rule Class Naming

- Use **PascalCase** for class names (e.g., `MyCheck`, `ApprovedTags`)
- Use **descriptive names** that clearly indicate what the rule checks
- The rule identifier (used in error messages) is automatically derived from the class name in lowercase

### Error Messages

Make error messages:
- **Clear and actionable**: Tell users what's wrong and how to fix it
- **Include context**: Always include the rule ID when available
- **Be consistent**: Follow the format used by existing rules

Example:
```python
desc=f"Rule is missing required action 'my_action'; rule id: {rule_id}"
```

### Testing Standards

- **One test per scenario**: Don't combine multiple test cases in one function
- **Descriptive test names**: Use names like `test_my_check_detects_missing_action()`
- **Always clean up**: Use try/finally to ensure temporary files are deleted
- **Test both success and failure**: Every rule should have tests for both valid and invalid cases

---

## Example: Complete Implementation

Here's a complete example of adding a new rule to check that rules have a `msg` action:

### 1. Create `src/crs_linter/rules/message_check.py`:

```python
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class MessageCheck(Rule):
    """Check that every rule has a 'msg' action.

    This rule verifies that all SecRule directives include a msg action
    to provide a human-readable description of what the rule detected.
    This is important for logging and debugging purposes.

    Example of a failing rule (missing msg):
        SecRule REQUEST_URI "@rx malicious" \\
            "id:1001,\\
            phase:2,\\
            deny,\\
            t:none"  # Fails: no msg action

    Example of a passing rule:
        SecRule REQUEST_URI "@rx malicious" \\
            "id:1002,\\
            phase:2,\\
            deny,\\
            t:none,\\
            msg:'Malicious request detected'"  # Correct: has msg action
    """

    def __init__(self):
        super().__init__()
        self.success_message = "All rules have msg action."
        self.error_message = "Found rules without msg action"
        self.error_title = "Missing msg action"
        self.args = ("data",)

    def check(self, data):
        """Check that every SecRule has a msg action."""
        for rule in data:
            if rule["type"].lower() != "secrule":
                continue

            # Get rule ID
            rule_id = 0
            has_msg = False

            if "actions" in rule:
                for action in rule["actions"]:
                    if action["act_name"] == "id":
                        rule_id = int(action["act_arg"])
                    if action["act_name"] == "msg":
                        has_msg = True

            # Yield problem if msg is missing
            if not has_msg and rule_id > 0:
                yield LintProblem(
                    line=rule.get("lineno", 0),
                    end_line=rule.get("lineno", 0),
                    desc=f"Rule is missing 'msg' action; rule id: {rule_id}",
                    rule="messagecheck"
                )
```

### 2. Create `tests/test_message_check.py`:

```python
import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_message_check_passes():
    """Test that rules with msg action pass."""
    valid_rule = (
        'SecRule REQUEST_URI "@rx malicious" \\\n'
        '    "id:1002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    t:none,\\\n'
        '    msg:\'Malicious request\'"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(valid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(valid_rule)
        linter = Linter(parsed, filename=temp_file, file_content=valid_rule)
        problems = list(linter.run_checks())

        msg_problems = [p for p in problems if p.rule == "messagecheck"]
        assert len(msg_problems) == 0
    finally:
        os.unlink(temp_file)


def test_message_check_fails():
    """Test that rules without msg action are caught."""
    invalid_rule = (
        'SecRule REQUEST_URI "@rx malicious" \\\n'
        '    "id:1001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    t:none"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(invalid_rule)
        temp_file = f.name

    try:
        parsed = parse_config(invalid_rule)
        linter = Linter(parsed, filename=temp_file, file_content=invalid_rule)
        problems = list(linter.run_checks())

        msg_problems = [p for p in problems if p.rule == "messagecheck"]
        assert len(msg_problems) > 0
        assert "msg" in msg_problems[0].desc.lower()
    finally:
        os.unlink(temp_file)
```

### 3. Generate documentation:

```bash
uv run python generate_rules_docs.py
```

### 4. Run tests:

```bash
uv run pytest tests/test_message_check.py
```

---

## Submitting Your Contribution

1. **Run all tests**: Make sure all tests pass
   ```bash
   uv run pytest
   ```

2. **Generate documentation**: Update the README
   ```bash
   uv run python generate_rules_docs.py
   ```

3. **Test your rule**: Try it on actual CRS files to ensure it works correctly

4. **Create a pull request**: Include:
   - Description of what the rule checks
   - Why it's important for CRS
   - Examples of rules it will catch
   - Any related CRS issues or PRs

---

## Questions or Need Help?

- **Issues**: https://github.com/coreruleset/crs-linter/issues

Thank you for contributing to CRS Linter! 🛡️
