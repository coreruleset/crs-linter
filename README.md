# 🛡️ CRS Linter

> A powerful linting tool for OWASP CRS configs

The CRS Linter helps maintain code quality and consistency across your rule configurations by automatically checking for common issues, style violations, and best practices.

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Command Line Arguments](#-command-line-arguments)
- [Output Formats](#-output-formats)
- [Exemptions](#-exemptions)
- [Linting Rules Reference](#-linting-rules-reference)

---

## 🔧 Prerequisites

**Python 3.7+** is required to run this tool.

---

## 📦 Installation

Install using PyPi:

```bash
pip3 install crs-linter
```

---

## 🚀 Quick Start

The basic usage requires three main arguments:

```bash
crs-linter \
  -d /path/to/coreruleset \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS
```

### Complete Example

Here's a full example with all recommended options (run from the `coreruleset` directory):

```bash
../crs-linter/src/crs_linter/cli.py \
  --debug \
  -r crs-setup.conf.example \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS \
  -f ../crs-linter/FILENAME_EXCLUSIONS \
  -v "4.13.0-dev"
```

---

## ⚙️ Command Line Arguments

### Required Arguments

| Argument | Description |
|----------|-------------|
| `-d, --directory` | Path to the CRS git repository (required if version is not provided) |
| `-r, --rules` | CRS rules file(s) to check (can be used multiple times). Supports glob patterns like `'rules/*.conf'` |
| `-t, --tags-list` | Path to the approved tags file. Tags not in this file will trigger validation errors |

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `-h, --help` | Show usage information and exit |
| `-o, --output` | Output format: `native` (default) or `github` |
| `--debug` | Enable debug information output |
| `-v, --version` | CRS version string (auto-detected if not provided) |
| `-f, --filename-tags-exclusions` | Path to file containing filenames exempt from filename tag checks |
| `-T, --tests` | Path to test files directory |
| `-E, --filename-tests-exclusions` | Path to file with rule ID prefixes excluded from test coverage checks |
| `--head-ref` | Git HEAD ref from CI pipeline (helps determine version) |
| `--commit-message` | PR commit message from CI (helps determine version for release commits) |

### Getting Help

To see all available options:

```bash
crs-linter -h
```

Example output:

```bash
usage: crs-linter [-h] [-o {native,github}] -d DIRECTORY [--debug] -r CRS_RULES -t TAGSLIST [-v VERSION] [--head-ref HEAD_REF] [--commit-message COMMIT_MESSAGE]
                  [-f FILENAME_TAGS_EXCLUSIONS] [-T TESTS] [-E FILENAME_TESTS_EXCLUSIONS]
crs-linter: error: the following arguments are required: -d/--directory, -r/--rules, -t/--tags-list
```

---

## 📤 Output Formats

### Native Format (Default)

Standard human-readable output format:

```bash
crs-linter -d /path/to/crs -r 'rules/*.conf' -t util/APPROVED_TAGS
```

### GitHub Actions Format

Specially formatted output for GitHub Actions workflows with `::debug` and `::error` prefixes:

```bash
crs-linter \
  --output=github \
  -d /path/to/crs \
  -r 'rules/*.conf' \
  -t util/APPROVED_TAGS
```

This format follows [GitHub's workflow commands specification](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-a-notice-message) for better CI/CD integration.

---

## 🔕 Exemptions

Sometimes you may need to suppress specific linting rules for individual ModSecurity rules. The CRS Linter supports exemption comments that allow you to selectively disable checks.

### Format

```apache
#crs-linter:ignore:rule1,rule2,rule3
```

- **Keywords** (`crs-linter`, `ignore`) are case-insensitive
- **Rule names** are comma-separated (use the rule name from the error message)
- Whitespace around colons and commas is allowed
- The exemption applies to the **next non-comment, non-blank line**

### Available Rule Names

<!-- GENERATED_EXEMPTIONS_DOCS_START -->
The following rule names can be used in exemption comments:

| Rule name | Description |
| --- | --- |
| `approved_tags` | [ApprovedTags](#approvedtags) |
| `capture` | [CheckCapture](#checkcapture) |
| `crs_tag` | [CrsTag](#crstag) |
| `deprecated` | [Deprecated](#deprecated) |
| `duplicated` | [DuplicatedIds](#duplicatedids) |
| `ignore_case` | [IgnoreCase](#ignorecase) |
| `indentation` | [Indentation](#indentation) |
| `lowercase_ignorecase` | [LowercaseIgnorecase](#lowercaseignorecase) |
| `ordered_actions` | [OrderedActions](#orderedactions) |
| `pass_nolog` | [PassNolog](#passnolog) |
| `pl_consistency` | [PlConsistency](#plconsistency) |
| `rule_tests` | [RuleTests](#ruletests) |
| `standalonetxn` | [StandaloneTxn](#standalonetxn) |
| `variables_usage` | [VariablesUsage](#variablesusage) |
| `version` | [Version](#version) |
<!-- GENERATED_EXEMPTIONS_DOCS_END -->

### Examples

#### Exempt a single rule

```apache
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \
    "id:1001,\
    phase:1,\
    pass,\
    t:lowercase"
```

#### Exempt multiple rules

```apache
#crs-linter:ignore:lowercase_ignorecase,deprecated
SecRule REQUEST_HEADERS:Referer "@rx (?i)attack" \
    "id:1002,\
    phase:1,\
    deny,\
    t:lowercase"
```

#### Skip comments and blank lines

Exemption comments automatically skip over other comments and blank lines to find the target rule:

```apache
#crs-linter:ignore:lowercase_ignorecase
# This comment is skipped

# Blank lines are also skipped
SecRule ARGS "@rx (?i)bar" \
    "id:1003,\
    phase:1,\
    pass,\
    t:lowercase"
```

#### Multiple exemption comments

Multiple exemption comments for the same rule are merged:

```apache
#crs-linter:ignore:lowercase_ignorecase
#crs-linter:ignore:deprecated
SecRule REQUEST_HEADERS:Referer "@rx (?i)test" \
    "id:1004,\
    phase:1,\
    deny,\
    t:lowercase"
```

### Important Notes

- Each exemption only affects the **immediate next rule**
- Exemptions work with multi-line rules (the entire rule is exempted)
- Unknown rule names trigger a warning to help catch typos
- Case variations in keywords are supported: `#CRS-LINTER:IGNORE:rule_name`

### See Also

- [Exemption examples file](examples/exemption_example.conf) - Comprehensive examples
- [Rule names reference](#-linting-rules-reference) - List of all available rule names

---

<!-- GENERATED_RULES_DOCS_START -->
# 📖 Linting Rules Reference

This section is automatically generated from the Python docstrings in `src/crs_linter/rules/`.

> 💡 **To update this documentation**: Edit the docstrings in the rule class files and run `python generate_rules_docs.py`.

## ApprovedTags

**Source:** `src/crs_linter/rules/approved_tags.py`

Check that only tags from the util/APPROVED_TAGS file are used.

This rule verifies that all tags used in rules are registered in the
util/APPROVED_TAGS file. Any tag not listed in this file will be
considered a check failure.

Example of a failing rule:

```apache
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss,\
    tag:my-custom-tag"  # Fails if 'my-custom-tag' not in APPROVED_TAGS
```


To use a new tag on a rule, it must first be registered in the
util/APPROVED_TAGS file.

## CheckCapture

**Source:** `src/crs_linter/rules/check_capture.py`

Check that rules using TX.N variables have a corresponding `capture` action.

This rule ensures that captured transaction variables (TX:0, TX:1, TX:2, etc.)
are only used when a `capture` action has been defined in the rule chain.

TX.N variables can be referenced in multiple ways:
1. As a rule target: `SecRule TX:1 "@eq attack"`
2. In action arguments: `msg:'Matched: %{TX.1}'`, `logdata:'Data: %{TX.0}'`
3. In operator arguments: `@rx %{TX.1}`
4. In setvar assignments: `setvar:tx.foo=%{TX.1}`

Example of a passing rule (with capture):

```apache
SecRule ARGS "@rx (attack)" \
    "id:2,\
    phase:2,\
    deny,\
    capture,\
    msg:'Attack detected: %{TX.1}',\
    logdata:'Pattern: %{TX.0}',\
    chain"
    SecRule TX:1 "@eq attack"
```


Example of a failing rule (missing capture for target):

```apache
SecRule ARGS "@rx attack" \
    "id:3,\
    phase:2,\
    deny,\
    t:none,\
    nolog,\
    chain"
    SecRule TX:0 "@eq attack"  # Fails: uses TX:0 without capture
```


Example of a failing rule (missing capture for action argument):

```apache
SecRule ARGS "@rx attack" \
    "id:4,\
    phase:2,\
    deny,\
    msg:'Matched: %{TX.1}'"  # Fails: references TX.1 without capture
```


This check addresses the issue found in CRS PR #4265 where %{TX.N} was
used in action arguments without verifying that capture was defined.

## CrsTag

**Source:** `src/crs_linter/rules/crs_tag.py`

Check that every rule has a `tag:'OWASP_CRS'` action and a tag for its filename.

This rule verifies that:
1. Every rule has a tag with value 'OWASP_CRS'
2. Every non-administrative rule has a tag with value 'OWASP_CRS/$filename$'

Example of a failing rule (missing OWASP_CRS tag):

```apache
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:attack-xss"  # Fails: missing tag:OWASP_CRS
```


Example of a passing rule:

```apache
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    tag:OWASP_CRS/test11"
```


Files can be excluded from filename tag checking using the -f flag with
a list of excluded files (see FILENAME_EXCLUSIONS for an example).

## Deprecated

**Source:** `src/crs_linter/rules/deprecated.py`

Check for deprecated patterns in rules.

This is a general-purpose rule for checking deprecated patterns that may be
removed in future CRS versions. Currently checks for ctl:auditLogParts.

Example of a failing rule (using deprecated ctl:auditLogParts):

```apache
SecRule TX:sql_error_match "@eq 1" \
    "id:1,\
    phase:4,\
    block,\
    capture,\
    t:none,\
    ctl:auditLogParts=+E"  # Fails: ctl:auditLogParts is deprecated
```


The ctl:auditLogParts action is no longer supported in CRS (see PR #3034).

Note: This overlaps with ctl_audit_log.py which checks the same pattern but
treats it as "not allowed" rather than "deprecated". Consider consolidating
these rules if they serve the same purpose.

## DuplicatedIds

**Source:** `src/crs_linter/rules/duplicated.py`

Check for duplicated rule IDs.

This rule ensures that each rule has a unique ID across all configuration
files in the ruleset.

Example of failing rules (duplicate IDs):

```apache
SecRule ARGS "@rx foo" \
    "id:1001,\
    phase:2,\
    block,\
    capture,\
    t:none"
```



```apache
SecRule ARGS_NAMES "@rx bar" \
    "id:1001,\  # Fails: ID 1001 is already used above
    phase:2,\
    block,\
    capture,\
    t:none"
```

## IgnoreCase

**Source:** `src/crs_linter/rules/ignore_case.py`

Check the ignore cases at operators, actions, transformations and ctl arguments.

This rule verifies that operators, actions, transformations, and ctl
arguments use the proper case-sensitive format. CRS requires specific
casing for these elements even though ModSecurity itself may be case-
insensitive. This rule also ensures that an operator is explicitly
specified.

Example of a failing rule (incorrect operator case):

```apache
SecRule REQUEST_URI "@beginswith /index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog"  # Fails: @beginswith should be @beginsWith
```


Example of a failing rule (missing operator):

```apache
SecRule REQUEST_URI "index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog"  # Fails: empty operator isn't allowed, must use @rx
```


ModSecurity defaults to @rx when no operator is specified, but CRS
requires explicit operators for clarity.

## Indentation

**Source:** `src/crs_linter/rules/indentation.py`

Check for indentation errors in rules.

This rule verifies that rule files follow CRS formatting guidelines for
indentation and whitespace. The linter uses msc_pyparser to regenerate
the formatted version of each file and compares it with the original
using difflib to detect any formatting discrepancies.

Example of failing rules (incorrect indentation):

```apache
 SecRule ARGS "@rx foo" \  # Extra leading space
   "id:1,\  # Wrong indentation (should be 4 spaces)
    phase:1,\
    pass,\
    nolog"
```



```apache
SecRule ARGS "@rx foo" \
     "id:3,\  # Extra leading space
    phase:1,\
    pass,\
    nolog"
```


Example of correct indentation:

```apache
SecRule ARGS "@rx foo" \
    "id:2,\
    phase:1,\
    pass,\
    nolog"
```

## LowercaseIgnorecase

**Source:** `src/crs_linter/rules/lowercase_ignorecase.py`

Check for combined transformation and ignorecase patterns.

This rule detects when rules use both the t:lowercase transformation and
the (?i) case-insensitive regex flag together. This combination is
redundant and should be avoided - use one or the other.

Example of a failing rule (combining t:lowercase and (?i)):

```apache
SecRule ARGS "@rx (?i)foo" \
    "id:1,\
    phase:1,\
    pass,\
    t:lowercase,\  # Fails: redundant with (?i) flag
    nolog"
```


The rule should use either:
- t:lowercase with a case-sensitive regex: "@rx foo"
- (?i) flag without t:lowercase transformation

## OrderedActions

**Source:** `src/crs_linter/rules/ordered_actions.py`

Check that actions are in the correct order.

This rule verifies that actions in rules follow the CRS-specified order.
The first action must be 'id', followed by 'phase', and then other
actions in their designated order.

Example of a failing rule (wrong action order):

```apache
SecRule REQUEST_URI "@beginsWith /index.php" \
    "phase:1,\  # Wrong: phase should come after id
    id:1,\
    deny,\
    t:none,\
    nolog"
```


Example of a correct rule:

```apache
SecRule REQUEST_URI "@beginsWith /index.php" \
    "id:1,\  # Correct: id comes first
    phase:1,\  # Correct: phase comes second
    deny,\
    t:none,\
    nolog"
```

## PassNolog

**Source:** `src/crs_linter/rules/pass_nolog.py`

Check that rules using the `pass` action also include `nolog`.

When a rule uses the `pass` disruptive action (allowing the request to
continue), it should also include `nolog` to prevent excessive log spam.
Rule logging is only meaningful for blocking rules or for debugging
purposes.

Example of a failing rule (pass without nolog):

```apache
SecRule ARGS "@rx foo" \
    "id:1,\
    phase:2,\
    pass,\
    t:none"  # Fails: pass without nolog
```


Example of a correct rule:

```apache
SecRule ARGS "@rx foo" \
    "id:2,\
    phase:2,\
    pass,\
    t:none,\
    nolog"  # OK: nolog accompanies pass
```


Note: This check applies to any directive that supports actions, including
SecRule and SecAction.

## PlConsistency

**Source:** `src/crs_linter/rules/pl_consistency.py`

Check the paranoia-level consistency.

This rule verifies that rules activated for a specific paranoia level (PL)
have consistent tags and anomaly scoring variables. It checks:

1. Rules on PL N must have tag 'paranoia-level/N'
2. Rules must not have paranoia-level tag if they have 'nolog' action
3. Anomaly score variables must match the current PL (e.g., pl1 for PL1)
4. Severity must match the anomaly score variable being set
5. Rules must have severity action when setting anomaly scores

Example of failing rules:

```apache
# Rule activated on PL1 but tagged as PL2
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920160,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/2',\  # Wrong: should be paranoia-level/1
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
    # Also wrong: severity CRITICAL but using error_anomaly_score
```



```apache
# Rule missing severity action
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920161,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/1',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
    # Missing severity action
```



```apache
# Rule setting wrong PL variable
SecRule REQUEST_HEADERS:Content-Length "!@rx ^\d+$" \
    "id:920162,\
    phase:1,\
    block,\
    t:none,\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
    # Wrong: using pl2 variable on PL1
```

## RuleTests

**Source:** `src/crs_linter/rules/rule_tests.py`

Check that rules have corresponding test cases.

This rule verifies that each rule has at least one corresponding test
case in the test suite. Rules without tests are flagged to ensure
adequate test coverage.

The check skips:
- Paranoia level control rules (rule IDs with last two digits < 100)
- Rules in the exclusion list (configured via -E flag)

Example of a failing rule (no corresponding tests):

```apache
SecRule REQUEST_URI "@rx malicious" \
    "id:942100,\  # Fails if no test case references rule 942100
    phase:2,\
    block,\
    t:none,\
    tag:OWASP_CRS"
```


To fix: Add a test case to your test suite that exercises this rule.

Use the -E flag to provide a file with rule ID prefixes that should be
excluded from this check.

## StandaloneTxn

**Source:** `src/crs_linter/rules/standalone_txn.py`

Check that TX.N variables are not used as targets in standalone rules.

This rule prevents TX.N capture group variables (TX:0, TX:1, TX:2, etc.)
from being used as rule targets in standalone rules. Standalone rules have
no control over what values exist in TX.N from previous unrelated rules,
making such usage unpredictable and error-prone.

TX.N variables should only be used in chained rules where the parent rule
in the chain sets the value (typically via regex matching).

Example of a failing rule (standalone rule using TX.N):

```apache
SecRule "TX:4" "@eq 1" \
    "id:3,\
    phase:2,\
    deny"  # Fails: standalone rule using TX:4
```


Example of a passing rule (chained rule using TX.N):

```apache
SecRule ARGS "@rx (ab|cd)?(ef)" \
    "id:1,\
    phase:2,\
    deny,\
    chain"
    SecRule "TX:1" "@eq ef"  # OK: TX:1 used in chained rule
```


Note: This check complements the CheckCapture rule, which ensures that
TX.N usage requires a capture action. This rule specifically addresses
the issue of TX.N in standalone rules where values are unpredictable.

## VariablesUsage

**Source:** `src/crs_linter/rules/variables_usage.py`

Check if a used TX variable has been set.

This rule ensures that all TX variables are initialized before they are
used. A variable is considered "used" when it appears:
- As a target in a rule (e.g., SecRule TX:foo ...)
- In an operator argument (e.g., @rx %{TX.foo})
- As a right-hand side value in setvar (e.g., setvar:tx.bar=%{tx.foo})
- In an expansion (e.g., msg:'Value: %{tx.foo}')

Example of failing rules (uninitialized variable):

```apache
SecRule TX:foo "@rx bar" \
    "id:1001,\
    phase:1,\
    pass,\
    nolog"  # Fails: TX:foo used but never set
```



```apache
SecRule ARGS "@rx ^.*$" \
    "id:1002,\
    phase:1,\
    pass,\
    nolog,\
    setvar:tx.bar=1"  # Warning: tx.bar set but never used
```


The linter also reports unused TX variables - variables that are set but
never referenced anywhere in the ruleset.

## Version

**Source:** `src/crs_linter/rules/version.py`

Check that every rule has a `ver` action with the correct version.

This rule verifies that all rules have a 'ver' action with the correct
CRS version string. The version can be specified manually using the -v
flag, or automatically extracted from git tags using 'git describe --tags'.

Example of failing rules:

```apache
# Missing 'ver' action
SecRule REQUEST_URI "@rx index.php" \
    "id:1,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS"  # Fails: no ver action
```



```apache
# Incorrect 'ver' value
SecRule REQUEST_URI "@rx index.php" \
    "id:2,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:OWASP_CRS/1.0.0-dev"  # Fails if expected version is 4.6.0-dev
```


Example of a correct rule:

```apache
SecRule REQUEST_URI "@rx index.php" \
    "id:3,\
    phase:1,\
    deny,\
    t:none,\
    nolog,\
    tag:OWASP_CRS,\
    ver:'OWASP_CRS/4.6.0-dev'"
```
<!-- GENERATED_RULES_DOCS_END -->
