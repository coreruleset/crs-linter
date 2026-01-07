# CRS Linter - Copilot Coding Agent Instructions

## Project Overview

**CRS Linter** is a powerful linting tool for OWASP Core Rule Set (CRS) configurations written in Python. It validates ModSecurity rule files against CRS coding standards, checking for proper formatting, required tags, version consistency, paranoia levels, and other rule-specific requirements.

- **Repository Size**: ~2,300 lines of Python code
- **Language**: Python 3.11+ (tested on 3.11, 3.12, 3.13)
- **Primary Dependencies**: msc_pyparser (ModSecurity config parser), dulwich (Git operations), semver, github-action-utils
- **Package Manager**: `uv` (modern Python package manager)
- **Build System**: hatchling with hatch-vcs for version management
- **Testing**: pytest with pytest-cov
- **Project Type**: CLI tool installable via PyPI

## Installation and Environment Setup

### Prerequisites
- Python 3.11 or higher (3.11, 3.12, 3.13 are tested)
- `uv` package manager (can be installed via `pip install uv`)

### Initial Setup
**ALWAYS run these commands in order when working with this repository:**

```bash
# Install uv if not available
pip install uv

# Install all dependencies (ALWAYS run this before building or testing)
uv sync --all-extras --dev
```

**Important**: The `uv sync --all-extras --dev` command installs both runtime and development dependencies. This command takes approximately 10-15 seconds to complete and is required before running any other commands.

## Building the Project

### Build the Package
```bash
# Build source distribution and wheel
uv build
```

**Build Time**: Approximately 5-10 seconds

**Build Output**: Creates `dist/` directory with:
- Source distribution (`.tar.gz`)
- Wheel distribution (`.whl`)

**Known Build Warning**: You may see a warning about shallow git repository when building. This is normal and does not affect functionality:
```
UserWarning: "..." is shallow and may cause errors
```

## Testing

### Running Tests

**ALWAYS run tests using this exact command:**

```bash
uv run pytest -vs
```

**Test Suite Details**:
- **Total Tests**: 256 tests
- **Expected Result**: All 256 tests should pass
- **Test Duration**: Approximately 1 second
- **Test Files Location**: `tests/` directory

**Test Coverage**:
- Unit tests for all linting rules
- CLI functionality tests
- Parser and utility function tests
- Integration tests with example configurations

**Running Specific Tests**:
```bash
# Run specific test file
uv run pytest tests/test_linter.py -vs

# Run specific test function
uv run pytest tests/test_linter.py::test_function_name -vs

# Run with coverage report
uv run pytest --cov=crs_linter -vs
```

**Important**: DO NOT run tests without the `uv run` prefix, as this ensures the correct virtual environment is used.

## Documentation Generation

The README.md contains auto-generated documentation from rule class docstrings.

**To update documentation after modifying rule docstrings:**

```bash
uv run python generate_rules_docs.py
```

**Check if README is up to date:**
```bash
uv run python generate_rules_docs.py --check
```

**ALWAYS run the documentation generator before committing if you've modified any rule class docstrings in `src/crs_linter/rules/*.py`.**

## Running the Linter

### Basic Usage
```bash
uv run crs-linter \
  -d /path/to/coreruleset \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS
```

### CLI Options
- `-d, --directory`: Path to CRS git repository (required if version not provided)
- `-r, --rules`: Rule file(s) to check (can be used multiple times, supports glob patterns)
- `-t, --tags-list`: Path to approved tags file
- `-v, --version`: CRS version string (auto-detected from git if not provided)
- `-o, --output`: Output format (`native` or `github`)
- `--debug`: Enable debug information
- `-f, --filename-tags`: Path to filename tag exclusions file
- `-T, --test-directory`: Path to CRS tests directory
- `-E, --filename-tests`: Path to test exclusions file

## Project Structure

### Root Directory Files
```
.github/             # GitHub Actions workflows and configurations
.gitignore           # Standard Python .gitignore
CHANGES.md           # Version history (minimal, v0.1 initial release)
CONTRIBUTING.md      # Guide for adding new linting rules
DEVELOPMENT.md       # Developer guide for rule architecture
LICENSE              # Apache 2.0 license
README.md            # Main documentation with auto-generated rule docs
TODO.txt             # Project TODO list
examples/            # Example configuration files for testing
generate_rules_docs.py  # Script to generate rule documentation
pyproject.toml       # Project configuration and dependencies
renovate.json        # Renovate bot configuration for dependency updates
src/                 # Source code directory
tests/               # Test files
uv.lock              # Locked dependencies (managed by uv)
```

### Source Code Structure (`src/crs_linter/`)
```
cli.py              # Command-line interface entry point (main function)
linter.py           # Main Linter class that orchestrates all rules
rule.py             # Base Rule class with metaclass for auto-registration
rules_metadata.py   # Rules metadata and management system
lint_problem.py     # LintProblem class for reporting issues
logger.py           # Logger with native and GitHub Actions output formats
utils.py            # Utility functions (version parsing, ID extraction, etc.)
rules/              # Directory containing all linting rule implementations
  approved_tags.py      # Check tags against APPROVED_TAGS file
  check_capture.py      # Verify capture action for TX.N variables
  crs_tag.py            # Check OWASP_CRS and filename tags
  deprecated.py         # Check for deprecated patterns
  duplicated.py         # Check for duplicate rule IDs
  ignore_case.py        # Check operator/action case sensitivity
  indentation.py        # Check formatting and indentation
  lowercase_ignorecase.py  # Check redundant lowercase + (?i) patterns
  ordered_actions.py    # Verify action ordering (id, phase, etc.)
  pl_consistency.py     # Check paranoia level consistency
  rule_tests.py         # Verify test coverage for rules
  variables_usage.py    # Check TX variable initialization
  version.py            # Verify version action correctness
```

### Test Structure (`tests/`)
```
conftest.py         # Pytest fixtures and configuration
test_*.py           # Test files (one per module/rule)
```

## GitHub Workflows and CI

### Workflows Location
`.github/workflows/`

### Active Workflows

**1. Regression Tests** (`.github/workflows/test.yml`)
- **Triggers**: Push to main, Pull requests to main
- **Python Versions**: 3.11, 3.12, 3.13
- **CRS Version Tested**: 4.22.0 (updated by Renovate bot)
- **Steps**:
  1. Checkout repository
  2. Install uv
  3. Set up Python
  4. Run `uv sync --all-extras --dev`
  5. Run unit tests: `uv run pytest -vs`
  6. Download CRS release and run linter against it

**2. PyPI Test Release** (`.github/workflows/pypi-test-release.yml`)
- **Triggers**: Pre-release published
- **Purpose**: Publish to Test PyPI for pre-release testing
- **Steps**:
  1. Checkout repository
  2. Set up Python
  3. Install uv (version 0.9.22)
  4. Run `uv build`
  5. Run `uv publish --index testpypi` to Test PyPI

**3. PyPI Release** (`.github/workflows/pypi-release.yml`)
- **Triggers**: Release published, manual workflow dispatch
- **Purpose**: Publish to production PyPI
- **Steps**:
  1. Checkout repository
  2. Set up Python
  3. Install uv (version 0.9.22)
  4. Run `uv build`
  5. Run `uv publish` to PyPI

**4. CodeQL Analysis** (`.github/workflows/codeql-analysis.yml`)
- **Triggers**: Push to master, Pull requests to master, Weekly schedule
- **Language**: Python
- **Purpose**: Security scanning
- **Note**: This workflow uses 'master' branch (legacy), but main branch is 'main' for development

## Architecture and Design Patterns

### Rule-Based Architecture
The linter uses a **metaclass-based auto-registration system** for rules:

1. **Base Rule Class** (`src/crs_linter/rule.py`): Abstract base class with `RuleMeta` metaclass
2. **Auto-Registration**: When a rule class is defined, it's automatically registered via metaclass
3. **No Manual Registration Needed**: Simply create a new rule file in `src/crs_linter/rules/` and import it in `linter.py`

### Rule Class Structure
```python
class MyRule(Rule):
    """Docstring becomes documentation (auto-extracted to README)."""
    
    def __init__(self):
        super().__init__()
        self.success_message = "Success message"
        self.error_message = "Error message"
        self.error_title = "Error title"
        self.args = ("data",)  # Arguments for check() method
        # Optional:
        # self.kwargs = {}
        # self.condition_func = lambda **kwargs: condition
    
    def check(self, data):
        """Yield LintProblem objects for each issue found."""
        for rule in data:
            # Check logic here
            if problem_detected:
                yield LintProblem(
                    line=rule.get("lineno", 0),
                    end_line=rule.get("lineno", 0),
                    desc="Problem description",
                    rule="rulename"
                )
```

### Available Rule Arguments
Rules can request these arguments via `self.args`:
- `data`: Parsed rule structures from msc_pyparser
- `filename`: Path to current file
- `content`: Parsed content object (same as `data`)
- `file_content`: Raw file content as string
- `globtxvars`: Dictionary of TX variables (shared across all files)
- `ids`: Dictionary of rule IDs (shared across all files)
- `tags`/`tagslist`: List of approved tags
- `test_cases`: Dictionary of test cases
- `exclusion_list`: List of excluded tests
- `version`/`crs_version`: CRS version string

### Shared State Pattern
**Important**: `globtxvars` and `ids` are **shared across all files** during linting:
- Files are processed in **sorted alphabetical order**
- `crs-setup.conf.example` typically comes first and defines most TX variables
- Later files can reference variables defined in earlier files
- This enables cross-file validation (e.g., duplicate ID detection)

## Adding New Features

### Adding a New Linting Rule

**Steps**:
1. Create new file in `src/crs_linter/rules/my_rule.py`
2. Implement rule class inheriting from `Rule`
3. Add comprehensive docstring (becomes documentation)
4. Import in `src/crs_linter/linter.py`
5. Create tests in `tests/test_my_rule.py`
6. Run tests: `uv run pytest -vs`
7. Generate docs: `uv run python generate_rules_docs.py`

**See `CONTRIBUTING.md` for detailed guide with complete examples.**

### Modifying Existing Rules

**Before modifying**:
1. Locate the rule in `src/crs_linter/rules/`
2. Review existing tests in `tests/test_*.py`
3. Make changes
4. Run tests: `uv run pytest -vs`
5. Update docstring if behavior changed
6. Regenerate docs: `uv run python generate_rules_docs.py`

## Common Pitfalls and Workarounds

### Version Management
- **Issue**: Version is auto-detected from git tags using `git describe --tags`
- **Workaround**: If version detection fails, use `-v` flag to specify version manually
- **Note**: Shallow git clones may cause version detection warnings (non-fatal)

### File Processing Order
- **Critical**: Files are processed in **sorted alphabetical order**
- **Impact**: TX variable definitions from earlier files are visible in later files
- **Example**: `crs-setup.conf.example` (processed first) → `REQUEST-901-*.conf` (can use variables from setup)

### Parser Errors
- **Issue**: msc_pyparser may fail on syntax errors
- **Behavior**: Linter reports error and continues with next file
- **Error Types**: Lexer errors (tokenization) or Parser errors (grammar)

### Test Exclusions
- **Paranoia Level Rules**: Rules with IDs where `(id % 1000) < 100` are skipped from test coverage checks
- **Exclusion File**: Use `-E` flag to provide file with rule ID prefixes to exclude

## Code Style and Conventions

### Python Style
- **Indentation**: 4 spaces (PEP 8)
- **Imports**: Standard library, third-party, local (grouped and sorted)
- **Naming**: 
  - Classes: PascalCase
  - Functions/Variables: snake_case
  - Constants: UPPER_CASE

### Testing Style
- **One test per scenario**: Don't combine multiple cases in one function
- **Descriptive names**: `test_rule_detects_missing_action()`
- **Always clean up**: Use try/finally for temporary files
- **Test both success and failure**: Every rule needs positive and negative tests

### Error Messages
- **Clear and actionable**: Tell users what's wrong and how to fix it
- **Include context**: Always include rule ID when available
- **Format**: `"Problem description; rule id: {rule_id}"`

## Validation Steps

### Before Committing Code Changes

**ALWAYS run these validation steps in order**:

```bash
# 1. Run all tests
uv run pytest -vs

# 2. If docstrings were modified, regenerate documentation
uv run python generate_rules_docs.py

# 3. Verify build works
uv build

# 4. Check git status
git status
```

**All tests must pass (256/256) before committing.**

### Testing Against Real CRS Files

To validate against actual CRS configurations (mimics CI):

```bash
# Download and extract CRS
curl -sSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.22.0.tar.gz -o - | \
  tar xzvf - \
    --strip-components=1 \
    --wildcards "*/rules/*" "*/tests/*" "*/crs-setup.conf.example" "*/util/*"

# Run linter
uv run crs-linter \
  --debug \
  -o github \
  -d . \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS \
  -f util/FILENAME_EXCLUSIONS \
  -v 4.22.0 \
  -T tests/regression/tests/ \
  -E util/TESTS_EXCLUSIONS
```

## Performance Considerations

- **Test Suite**: Completes in ~1 second
- **Build Time**: 5-10 seconds
- **Installation**: 10-15 seconds for full dependency sync
- **Linting**: Depends on number of CRS files, typically 1-5 seconds for full ruleset

## Dependencies and Versions

### Runtime Dependencies
- `msc_pyparser >= 1.2.1`: ModSecurity config parser
- `dulwich >= 0.25.0, < 0.26.0`: Pure Python Git implementation
- `semver >= 3.0.2, < 4.0.0`: Semantic versioning
- `github-action-utils >= 1.1.0, < 2.0.0`: GitHub Actions integration

### Development Dependencies
- `pytest >= 9.0.1, < 10`: Testing framework
- `pytest-cov >= 7.0.0`: Coverage plugin

### Dependency Updates
- Managed by Renovate bot (see `renovate.json`)
- CRS version in CI tests is auto-updated by Renovate

## Key Files to Review

When making changes, these files are most relevant:

1. **pyproject.toml**: Dependencies, project metadata, build configuration
2. **src/crs_linter/cli.py**: CLI argument parsing and main entry point
3. **src/crs_linter/linter.py**: Main linter orchestration logic
4. **src/crs_linter/rule.py**: Base rule class and metaclass system
5. **.github/workflows/test.yml**: CI configuration

## Trust These Instructions

**These instructions have been validated by**:
- Running the complete installation process
- Executing all 256 tests successfully
- Building the package
- Testing CLI functionality
- Generating documentation
- Reviewing all workflows and configuration files

**If you find any discrepancy between these instructions and actual behavior, the instructions should be updated.**

## Quick Reference Commands

```bash
# Complete setup from scratch
pip install uv
uv sync --all-extras --dev

# Run tests
uv run pytest -vs

# Build package
uv build

# Generate documentation
uv run python generate_rules_docs.py

# Run linter (help)
uv run crs-linter -h

# Run specific test file
uv run pytest tests/test_linter.py -vs
```
