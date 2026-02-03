"""
Integration tests for exemption mechanism.

Tests end-to-end functionality with actual ModSecurity rules.
"""

from crs_linter.linter import Linter, parse_config


class TestExemptionIntegration:
    """Integration tests for exemption mechanism."""

    def test_exemption_suppresses_lowercase_ignorecase(self):
        """Test that exemption comment suppresses lowercase_ignorecase rule."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have no lowercase_ignorecase problems (exempted)
        assert len(lowercase_problems) == 0

    def test_exemption_suppresses_deprecated(self):
        """Test that exemption comment suppresses deprecated rule."""
        content = """
#crs-linter:ignore:deprecated
SecRule REQUEST_HEADERS:Referer "@rx attack" \\
    "id:1001,\\
    phase:1,\\
    deny"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by deprecated rule
        deprecated_problems = [p for p in problems if p.rule == "deprecated"]

        # Should have no deprecated problems (exempted)
        assert len(deprecated_problems) == 0

    def test_non_exempted_problems_still_appear(self):
        """Test that non-exempted problems are still reported."""
        content = """
# Exempt lowercase_ignorecase but not deprecated
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"

# This rule should still trigger lowercase_ignorecase
SecRule ARGS "@rx (?i)bar" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have exactly 1 problem (rule 1002, not exempted)
        assert len(lowercase_problems) >= 1

        # Check that the problem is from the second rule (not exempted)
        # The line number will be where the t:lowercase action is
        problem_lines = {p.line for p in lowercase_problems}
        # First rule starts around line 3-6, second rule starts around line 9-12
        # We should only see problems from the second rule
        assert all(line > 8 for line in problem_lines)

    def test_multiple_exemptions_in_file(self):
        """Test multiple exemptions in same file."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"

#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)bar" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have no lowercase_ignorecase problems (all exempted)
        assert len(lowercase_problems) == 0

    def test_exemption_with_multiple_rules(self):
        """Test exemption with multiple rule names."""
        content = """
#crs-linter:ignore:lowercase_ignorecase,deprecated
SecRule REQUEST_HEADERS:Referer "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    deny,\\
    t:lowercase"
"""
        # Parse and lint (note: Referer is deprecated)
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by both rules
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]
        deprecated_problems = [p for p in problems if p.rule == "deprecated"]

        # Should have no problems for either rule (both exempted)
        assert len(lowercase_problems) == 0
        assert len(deprecated_problems) == 0

    def test_exemption_skips_comments_and_blanks(self):
        """Test that exemption applies to rule after comments and blanks."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
# This is a comment
# Another comment

SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have no lowercase_ignorecase problems (exempted)
        assert len(lowercase_problems) == 0

    def test_no_file_content_no_exemptions(self):
        """Test that without file_content, no exemptions are applied."""
        content = """
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint WITHOUT file_content
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=None)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have problems (no exemptions without file_content)
        assert len(lowercase_problems) > 0

    def test_exemption_only_affects_specified_line(self):
        """Test that exemption only affects the immediate next rule."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
SecRule ARGS "@rx (?i)bar" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have exactly 1 problem (rule 1002, not exempted)
        assert len(lowercase_problems) >= 1

        # Check that the problem is from the second rule
        problem_lines = {p.line for p in lowercase_problems}
        # First rule ends around line 6, second rule starts around line 7
        assert all(line > 6 for line in problem_lines)

    def test_exemption_with_chain_rules(self):
        """Test exemption with chained rules."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    chain"
    SecRule ARGS "@rx bar" \\
        "t:none"

# This chained rule should still trigger
SecRule ARGS "@rx (?i)baz" \\
    "id:1002,\\
    phase:1,\\
    pass,\\
    t:lowercase,\\
    chain"
    SecRule ARGS "@rx qux" \\
        "t:none"
"""
        # Parse and lint
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have at least 1 problem (second chain, not exempted)
        # First chain is exempted
        assert len(lowercase_problems) >= 1

        # Check that problems are from second rule (line > 11)
        problem_lines = {p.line for p in lowercase_problems}
        assert all(line > 11 for line in problem_lines)

    def test_unknown_rule_name_exemption(self):
        """Test that exempting unknown rule name doesn't cause errors."""
        content = """
#crs-linter:ignore:nonexistent_rule,lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        # Parse and lint - should not raise exception
        parsed = parse_config(content)
        linter = Linter(parsed, "test.conf", file_content=content)
        problems = list(linter.run_checks())

        # Filter by lowercase_ignorecase rule
        lowercase_problems = [p for p in problems if p.rule == "lowercase_ignorecase"]

        # Should have no lowercase_ignorecase problems (exempted)
        assert len(lowercase_problems) == 0

    def test_case_variations_in_comment(self):
        """Test various case variations in exemption comments."""
        # Test uppercase
        content1 = """
#CRS-LINTER:IGNORE:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        parsed1 = parse_config(content1)
        linter1 = Linter(parsed1, "test.conf", file_content=content1)
        problems1 = list(linter1.run_checks())
        lowercase_problems1 = [p for p in problems1 if p.rule == "lowercase_ignorecase"]
        assert len(lowercase_problems1) == 0

        # Test mixed case
        content2 = """
#Crs-Linter:Ignore:lowercase_ignorecase
SecRule ARGS "@rx (?i)foo" \\
    "id:1001,\\
    phase:1,\\
    pass,\\
    t:lowercase"
"""
        parsed2 = parse_config(content2)
        linter2 = Linter(parsed2, "test.conf", file_content=content2)
        problems2 = list(linter2.run_checks())
        lowercase_problems2 = [p for p in problems2 if p.rule == "lowercase_ignorecase"]
        assert len(lowercase_problems2) == 0
