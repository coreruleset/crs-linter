"""
Unit tests for exemption mechanism.
"""

import pytest
from crs_linter.exemptions import parse_exemptions, find_next_rule_line, should_exempt_problem
from crs_linter.lint_problem import LintProblem


class TestParseExemptions:
    """Test exemption comment parsing."""

    def test_basic_exemption(self):
        """Test basic exemption parsing with valid format."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 3 in exemptions
        end_line, rule_names = exemptions[3]
        assert 'lowercase_ignorecase' in rule_names
        assert end_line == 3

    def test_multiple_rules_in_exemption(self):
        """Test exemption with multiple rule names."""
        content = """
#crs-linter:ignore:lowercase_ignorecase,deprecated,duplicated
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 3 in exemptions
        end_line, rule_names = exemptions[3]
        assert rule_names == {'lowercase_ignorecase', 'deprecated', 'duplicated'}

    def test_whitespace_variations(self):
        """Test exemption parsing with various whitespace."""
        # Spaces around colons
        content1 = """
#crs-linter : ignore : lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions1 = parse_exemptions(content1)
        assert 3 in exemptions1
        end_line1, rule_names1 = exemptions1[3]
        assert 'lowercase_ignorecase' in rule_names1

        # Spaces around commas
        content2 = """
#crs-linter:ignore:lowercase_ignorecase , deprecated , duplicated
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions2 = parse_exemptions(content2)
        assert 3 in exemptions2
        end_line2, rule_names2 = exemptions2[3]
        assert rule_names2 == {'lowercase_ignorecase', 'deprecated', 'duplicated'}

        # Leading/trailing whitespace
        content3 = """
  #crs-linter:ignore:lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions3 = parse_exemptions(content3)
        assert 3 in exemptions3
        end_line3, rule_names3 = exemptions3[3]
        assert 'lowercase_ignorecase' in rule_names3

    def test_case_insensitivity(self):
        """Test case insensitivity of keywords."""
        # Uppercase keywords
        content1 = """
#CRS-LINTER:IGNORE:lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions1 = parse_exemptions(content1)
        assert 3 in exemptions1
        end_line1, rule_names1 = exemptions1[3]
        assert 'lowercase_ignorecase' in rule_names1

        # Mixed case keywords
        content2 = """
#Crs-Linter:Ignore:lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions2 = parse_exemptions(content2)
        assert 3 in exemptions2
        end_line2, rule_names2 = exemptions2[3]
        assert 'lowercase_ignorecase' in rule_names2

    def test_exemption_skips_blank_lines(self):
        """Test that exemption skips blank lines to find target."""
        content = """
#crs-linter:ignore:lowercase_ignorecase


SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 5 in exemptions
        end_line, rule_names = exemptions[5]
        assert 'lowercase_ignorecase' in rule_names

    def test_exemption_skips_comments(self):
        """Test that exemption skips comment lines to find target."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
# This is a comment
# Another comment
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 5 in exemptions
        end_line, rule_names = exemptions[5]
        assert 'lowercase_ignorecase' in rule_names

    def test_multiple_exemptions_same_line(self):
        """Test that multiple exemptions for same line are merged."""
        content = """
#crs-linter:ignore:lowercase_ignorecase
#crs-linter:ignore:deprecated
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 4 in exemptions
        end_line, rule_names = exemptions[4]
        assert rule_names == {'lowercase_ignorecase', 'deprecated'}

    def test_invalid_format_ignored(self):
        """Test that invalid format is silently ignored."""
        content = """
#crs-linter-ignore-lowercase_ignorecase
#crs-linter:lowercase_ignorecase
#ignore:lowercase_ignorecase
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert len(exemptions) == 0

    def test_empty_rule_list(self):
        """Test exemption with empty rule list."""
        content = """
#crs-linter:ignore:
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        # Should have entry but with empty set
        if 3 in exemptions:
            end_line, rule_names = exemptions[3]
            assert len(rule_names) == 0

    def test_unknown_rule_names(self):
        """Test that unknown rule names are stored."""
        content = """
#crs-linter:ignore:nonexistent_rule,another_fake_rule
SecRule ARGS "@rx foo" "id:1001"
"""
        exemptions = parse_exemptions(content)
        assert 3 in exemptions
        end_line, rule_names = exemptions[3]
        assert rule_names == {'nonexistent_rule', 'another_fake_rule'}

    def test_exemption_at_end_of_file(self):
        """Test exemption comment at end of file with no target."""
        content = """
SecRule ARGS "@rx foo" "id:1001"
#crs-linter:ignore:lowercase_ignorecase
"""
        exemptions = parse_exemptions(content)
        # No target line after exemption
        assert len(exemptions) == 0 or 3 not in exemptions

    def test_empty_content(self):
        """Test empty file content."""
        exemptions = parse_exemptions("")
        assert exemptions == {}

    def test_none_content(self):
        """Test None file content."""
        exemptions = parse_exemptions(None)
        assert exemptions == {}


class TestFindNextRuleLine:
    """Test finding next rule line."""

    def test_immediate_next_line(self):
        """Test finding rule on immediate next line."""
        lines = [
            "#crs-linter:ignore:rule",
            "SecRule ARGS"
        ]
        assert find_next_rule_line(lines, 0) == 2

    def test_skip_blank_lines(self):
        """Test skipping blank lines."""
        lines = [
            "#crs-linter:ignore:rule",
            "",
            "",
            "SecRule ARGS"
        ]
        assert find_next_rule_line(lines, 0) == 4

    def test_skip_comments(self):
        """Test skipping comment lines."""
        lines = [
            "#crs-linter:ignore:rule",
            "# Comment",
            "SecRule ARGS"
        ]
        assert find_next_rule_line(lines, 0) == 3

    def test_no_rule_found(self):
        """Test when no rule is found after exemption."""
        lines = [
            "#crs-linter:ignore:rule",
            "# Only comments after",
            ""
        ]
        assert find_next_rule_line(lines, 0) == 0


class TestShouldExemptProblem:
    """Test problem exemption logic."""

    def test_exempt_matching_problem(self):
        """Test exempting a matching problem."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        exemptions = {10: (10, {'lowercase_ignorecase'})}
        assert should_exempt_problem(problem, exemptions) is True

    def test_not_exempt_different_line(self):
        """Test not exempting problem on different line."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        exemptions = {5: (5, {'lowercase_ignorecase'})}
        assert should_exempt_problem(problem, exemptions) is False

    def test_not_exempt_different_rule(self):
        """Test not exempting problem with different rule."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        exemptions = {10: (10, {'deprecated'})}
        assert should_exempt_problem(problem, exemptions) is False

    def test_not_exempt_no_rule(self):
        """Test not exempting problem with no rule."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule=None)
        exemptions = {10: (10, {'lowercase_ignorecase'})}
        assert should_exempt_problem(problem, exemptions) is False

    def test_not_exempt_empty_exemptions(self):
        """Test not exempting when exemptions is empty."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        exemptions = {}
        assert should_exempt_problem(problem, exemptions) is False

    def test_exempt_multiple_rules(self):
        """Test exempting when line has multiple exemptions."""
        problem1 = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        problem2 = LintProblem(line=10, end_line=10, desc="Test", rule="deprecated")
        exemptions = {10: (10, {'lowercase_ignorecase', 'deprecated'})}
        assert should_exempt_problem(problem1, exemptions) is True
        assert should_exempt_problem(problem2, exemptions) is True

    def test_not_exempt_one_of_multiple(self):
        """Test not exempting rule not in exemption list."""
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="duplicated")
        exemptions = {10: (10, {'lowercase_ignorecase', 'deprecated'})}
        assert should_exempt_problem(problem, exemptions) is False

    def test_exempt_problem_within_range(self):
        """Test exempting problem that falls within rule range."""
        # SecRule on line 3-7, problem reported on line 7
        problem = LintProblem(line=7, end_line=7, desc="Test", rule="lowercase_ignorecase")
        exemptions = {3: (7, {'lowercase_ignorecase'})}
        assert should_exempt_problem(problem, exemptions) is True

    def test_not_exempt_problem_outside_range(self):
        """Test not exempting problem outside rule range."""
        # SecRule on line 3-7, problem reported on line 10
        problem = LintProblem(line=10, end_line=10, desc="Test", rule="lowercase_ignorecase")
        exemptions = {3: (7, {'lowercase_ignorecase'})}
        assert should_exempt_problem(problem, exemptions) is False
