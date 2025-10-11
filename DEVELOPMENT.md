# Guide for developers

This project uses the `uv` tool to manage dependencies and virtual environments. See [here](https://docs.astral.sh/uv/) for more details.

You can install all dependencies using `uv sync --all-extras --dev`.

## Testing

- Add tests in the `tests/` directory.
- Run tests with `uv run pytest -vs`.
- Add as many fixtures as you want in `tests/conftest.py`.

## Adding New Rules

The crs-linter uses a rule-based architecture where each linting check is implemented as a self-contained rule class. Rules are automatically registered using a metaclass system, so you only need to create the rule file - no manual registration required!

### 1. Create the Rule File

Create a new file in `src/crs_linter/rules/` with a descriptive name (e.g., `my_new_rule.py`):

```python
from crs_linter.lint_problem import LintProblem
from crs_linter.rule import Rule


class MyNewRule(Rule):
    """Description of what this rule checks."""

    def __init__(self):
        super().__init__()
        self.success_message = "My new rule check ok."
        self.error_message = "My new rule check found error(s)"
        self.error_title = "My new rule error"
        self.args = ("data",)  # Define expected arguments
        # Optional: self.kwargs = {"param": "value"}
        # Optional: self.condition_func = lambda **kwargs: some_condition

    def check(self, data):
        """
        Check for linting problems and yield LintProblem objects.
        
        Args:
            data: Parsed configuration data
            
        Yields:
            LintProblem: Linting problems found
        """
        for d in data:
            # Your rule logic here
            if some_condition:
                yield LintProblem(
                    line=d["lineno"],
                    end_line=d["lineno"],
                    desc="Description of the problem",
                    rule="my_new_rule",
                )
```

### 2. Define Rule Metadata

In the `__init__()` method, define the rule's metadata:

- **`success_message`**: Message shown when no problems are found
- **`error_message`**: Message shown when problems are found
- **`error_title`**: Title for error reporting
- **`args`**: Tuple of expected positional arguments
- **`kwargs`**: Dictionary of expected keyword arguments (optional)
- **`condition_func`**: Function to determine if rule should run (optional)

### 3. Implement the Check Logic

The `check()` method should:
- Accept the arguments defined in `self.args` and `self.kwargs`
- Iterate through the parsed configuration data
- Yield `LintProblem` objects for each issue found
- Use descriptive rule names in the `rule` parameter

### 4. Auto-Registration

**No manual registration needed!** The rule will be automatically registered when the linter module is imported. The metaclass system handles this automatically.

### 5. Add the Rule to the Linter

Add your rule import to `src/crs_linter/linter.py`:

```python
# Import all rules to trigger auto-registration via metaclass
from .rules import (
    # ... existing rules ...
    my_new_rule,  # Add your new rule here
)
```

### 6. Add Tests

Create tests in `tests/test_linter.py` or `tests/test_rules_metadata.py`:

```python
def test_my_new_rule():
    """Test the new rule functionality."""
    from crs_linter.rules.my_new_rule import MyNewRule
    
    rule = MyNewRule()
    sample_data = parse_config('SecRule ARGS "@rx ^test" "id:1,phase:1,log"')
    
    problems = list(rule.check(sample_data))
    
    # Assert expected behavior
    assert len(problems) == 0  # or expected number
```

### 7. Common Rule Patterns

#### Rules that need additional context:
```python
def __init__(self):
    super().__init__()
    self.args = ("data", "globtxvars")  # Access to TX variables
    # or
    self.args = ("data", "ids")  # Access to rule IDs
```

#### Rules with conditions:
```python
def __init__(self):
    super().__init__()
    self.condition_func = lambda **kwargs: kwargs.get('some_param') is not None
```

#### Rules that check specific patterns:
```python
def check(self, data):
    for d in data:
        if "actions" in d:
            for a in d["actions"]:
                if a["act_name"] == "specific_action":
                    # Check the action
                    pass
```

### 8. Rule Naming Conventions

- **Class names**: Use PascalCase (e.g., `MyNewRule`)
- **File names**: Use snake_case (e.g., `my_new_rule.py`)
- **Rule names**: Use snake_case (automatically derived from class name)
- **Descriptions**: Be clear and specific about what the rule checks

### 9. Testing Your Rule

Run the tests to ensure your rule works correctly:

```bash
# Test all rules
uv run pytest tests/test_linter.py tests/test_rules_metadata.py -v

# Test specific rule
uv run pytest tests/test_linter.py::test_my_new_rule -v
```

### 10. Integration with CLI

Your rule will automatically be available in the CLI once the linter module is imported. The linter will:
- Run your rule when appropriate conditions are met
- Display your success/error messages
- Report problems with your rule name

### 11. How Auto-Registration Works

The crs-linter uses a metaclass system for automatic rule registration:

1. **Metaclass**: The `Rule` base class uses `RuleMeta(ABCMeta)` metaclass
2. **Auto-Registration**: When a rule class is defined, the metaclass automatically creates an instance and registers it
3. **No Manual Work**: You don't need to manually register rules or create instances
4. **Import Trigger**: Rules are registered when the linter module imports them

### 12. Example: Complete Rule Implementation

See existing rules like `src/crs_linter/rules/ignore_case.py` or `src/crs_linter/rules/crs_tag.py` for complete examples of rule implementations.


