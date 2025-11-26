import glob
import tempfile
import os
from typing import Optional, List

import pytest
from crs_linter.linter import Linter, parse_config


@pytest.fixture(scope="session")
def crsversion():
    return "OWASP_CRS/4.10.0"


@pytest.fixture(scope="session")
def txvars():
    return {}


@pytest.fixture(scope="session")
def crs_files() -> list:
    files = glob.glob("../examples/*.conf")
    yield files


@pytest.fixture
def temp_rule_file():
    """Create a temporary rule file and clean it up after test."""
    temp_files = []

    def _create_temp_file(rule_content: str) -> str:
        """Create a temp file with the given rule content and return the path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(rule_content)
            temp_file = f.name
        temp_files.append(temp_file)
        return temp_file

    yield _create_temp_file

    # Cleanup
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


@pytest.fixture
def run_linter():
    """Run the linter on a rule and return problems for a specific rule type."""
    def _run_linter(
        rule: str,
        rule_type: Optional[str] = None,
        tagslist: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Run linter on a rule and return problems.

        Args:
            rule: The rule content as a string
            rule_type: Optional filter to return only problems for this rule type
            tagslist: Optional list of approved tags
            **kwargs: Additional arguments to pass to run_checks()

        Returns:
            List of LintProblems, filtered by rule_type if provided
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(rule)
            temp_file = f.name

        try:
            parsed = parse_config(rule)
            if parsed is None:
                raise ValueError(f"Failed to parse rule: {rule}")

            linter = Linter(parsed, filename=temp_file, file_content=rule)

            # Build kwargs for run_checks
            run_kwargs = {}
            if tagslist is not None:
                run_kwargs['tagslist'] = tagslist
            run_kwargs.update(kwargs)

            problems = list(linter.run_checks(**run_kwargs))

            if rule_type:
                return [p for p in problems if p.rule == rule_type]
            return problems
        finally:
            os.unlink(temp_file)

    return _run_linter


@pytest.fixture
def parse_rule():
    """Parse a rule and return the parsed structure."""
    def _parse(rule: str):
        parsed = parse_config(rule)
        if parsed is None:
            raise ValueError(f"Failed to parse rule: {rule}")
        return parsed
    return _parse
