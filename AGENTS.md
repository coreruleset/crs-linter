# AGENTS.md

Guidance for coding agents working on `crs-linter`. Human contributors: see `CONTRIBUTING.md` and `DEVELOPMENT.md`, which this file summarises and does not replace.

## What this is

`crs-linter` is a Python CLI that validates OWASP CRS (Core Rule Set) ModSecurity configuration files against CRS coding standards: formatting, tags, version consistency, paranoia levels, test coverage and so on. It is published on PyPI and run in CRS CI.

- Python 3.11+ (CI tests 3.11, 3.12, 3.13), managed with `uv`, built with hatchling and hatch-vcs.
- Parser: `msc_pyparser`. Other runtime dependencies: `dulwich`, `semver`, `github-action-utils`.

## Commands

```bash
uv sync --all-extras --dev                 # install dependencies (do this first)
uv run pytest -vs                          # unit tests (same command as CI)
uv run pytest tests/test_linter.py::test_name -vs   # one test
uv run python generate_rules_docs.py       # regenerate generated README sections
uv run python generate_rules_docs.py --check   # exit non-zero if README is stale
uv run crs-linter -h                       # CLI help
uv build                                   # build sdist and wheel
```

Always use the `uv run` prefix so the project virtual environment is used.

## Layout

```
src/crs_linter/
  cli.py              # entry point (main), argument and config-file handling
  linter.py           # Linter class: runs the registered rules over each file
  rule.py             # Rule base class + RuleMeta metaclass (auto-registration)
  rules_metadata.py   # registry of rules
  lint_problem.py     # LintProblem: line, end_line, desc, rule
  exemptions.py       # "#crs-linter:ignore:..." comment parsing
  logger.py           # native and GitHub Actions output formats
  utils.py
  rules/              # one file per lint rule
tests/                # pytest; roughly one test_*.py per rule or module
examples/             # sample configs
generate_rules_docs.py  # builds README sections from rule docstrings
```

## Working on lint rules

Each rule is a class deriving from `Rule` in `src/crs_linter/rules/<snake_case>.py`.

1. Set `success_message`, `error_message`, `error_title` and `args` (and optionally `kwargs`, `condition_func`) in `__init__`.
2. Implement `check(...)` as a generator yielding `LintProblem` objects. Its parameters must match `self.args`.
3. Write a full class docstring. It becomes the rule's documentation in `README.md`, including a failing and a passing example.
4. **Import the module in the `from .rules import (...)` block in `src/crs_linter/linter.py`.** Registration happens when the class is defined (the metaclass instantiates it), so the import is what triggers it. A rule file that is not imported there never runs.
5. Add tests, then regenerate the docs.

Available `args` include `data`, `filename`, `content`, `file_content`, `globtxvars`, `ids`, `tags`, `test_cases`, `exclusion_list` and `version`. See `Rules.get_rule_configs()` in `src/crs_linter/rules_metadata.py` for the supported mappings.

Things that are easy to get wrong:

- `globtxvars` and `ids` are shared across all files in a run, and files are processed in sorted order. `crs-setup.conf.example` comes first and defines most TX variables. Do not reset this state per file.
- Rule names are derived from the module file name (snake_case); the `rule=` string in a `LintProblem` should match what exemptions and tests refer to.
- Error messages should say what is wrong and how to fix it, and include the CRS rule id, for example `"Rule is missing required action 'x'; rule id: {rule_id}"`.
- A parser failure on one file is reported and the linter moves on to the next file; keep that behaviour.

## Exemptions

Users suppress findings for the next rule with a comment: `#crs-linter:ignore:rule1,rule2`. Keywords are case-insensitive and whitespace is tolerated. The exemption covers the next non-comment, non-blank line, extended over backslash continuations and `chain`ed rules. Logic is in `src/crs_linter/exemptions.py`; unknown rule names produce a warning.

## Tests

- Put tests in `tests/`; shared fixtures go in `tests/conftest.py`.
- One scenario per test function, with descriptive names such as `test_my_check_detects_missing_action`.
- Every rule needs a passing and a failing case. Clean up temporary files with `try/finally`.
- Run the full suite before committing: all tests must pass.

## Generated documentation

`README.md` contains sections generated from rule docstrings, between `<!-- GENERATED_RULES_DOCS_START -->` / `<!-- GENERATED_RULES_DOCS_END -->` and the equivalent `GENERATED_EXEMPTIONS_DOCS` markers. **Never edit between those markers by hand.** After changing a rule file or its docstring, run `uv run python generate_rules_docs.py`; `pre-commit.ci` also runs it on `src/crs_linter/rules/*.py` and `README.md`.

## Checking against real CRS

CI downloads a CRS release and lints it (see `.github/workflows/test.yml` for the exact current command and version). To reproduce locally, extract `rules/`, `tests/`, `crs-setup.conf.example` and `util/` from a CRS release tarball, then run `uv run crs-linter -d . -r crs-setup.conf.example -r 'rules/*.conf' -t <approved-tags> -v <version> -T tests/regression/tests/ ...`. Copy the flags from the workflow rather than from older docs.

## Commits, PRs and releases

- Releases are automated with release-please (`.github/release-please-config.json`): use Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`). Do not edit `version.txt` or `CHANGES.md` by hand.
- The version comes from git tags (`hatch-vcs`). Shallow clones may warn about it; that is harmless. Use `-v` to give the CLI a version explicitly.
- Dependencies are updated by Renovate. Do not hand-edit `uv.lock`; use `uv`.
- If AI tools helped write a change, say so in the PR description and state what you actually verified.

## Known stale docs

`.github/copilot-instructions.md` predates several changes (hard-coded test count, old CRS version, the `util/TESTS_EXCLUSIONS` path). Prefer this file, `CONTRIBUTING.md` and the CI workflow when they disagree.
