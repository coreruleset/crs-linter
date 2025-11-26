"""Tests for the LintProblem class."""

import pytest
from crs_linter.lint_problem import LintProblem


class TestLintProblemInit:
    """Tests for LintProblem initialization."""

    def test_init_with_all_parameters(self):
        """Test initialization with all parameters."""
        problem = LintProblem(
            line=10,
            end_line=15,
            column=5,
            desc="Test description",
            rule="test_rule"
        )

        assert problem.line == 10
        assert problem.end_line == 15
        assert problem.column == 5
        assert problem.desc == "Test description"
        assert problem.rule == "test_rule"
        assert problem.level is None

    def test_init_with_minimal_parameters(self):
        """Test initialization with minimal required parameters."""
        problem = LintProblem(line=5, end_line=5)

        assert problem.line == 5
        assert problem.end_line == 5
        assert problem.column is None
        assert problem.desc == '<no description>'
        assert problem.rule is None

    def test_init_sets_level_to_none(self):
        """Test that level is initialized to None."""
        problem = LintProblem(line=1, end_line=1)
        assert problem.level is None


class TestLintProblemMessage:
    """Tests for the message property."""

    def test_message_with_rule(self):
        """Test message property when rule is set."""
        problem = LintProblem(
            line=1,
            end_line=1,
            desc="Indentation error",
            rule="indentation"
        )

        assert problem.message == "Indentation error (indentation)"

    def test_message_without_rule(self):
        """Test message property when rule is None."""
        problem = LintProblem(
            line=1,
            end_line=1,
            desc="Generic error"
        )

        assert problem.message == "Generic error"

    def test_message_with_empty_rule(self):
        """Test message property when rule is empty string."""
        problem = LintProblem(
            line=1,
            end_line=1,
            desc="Error",
            rule=""
        )

        # Empty string is still added to message (not None)
        assert problem.message == "Error ()"


class TestLintProblemEquality:
    """Tests for __eq__ method."""

    def test_equal_problems(self):
        """Test that problems with same line, column, and rule are equal."""
        problem1 = LintProblem(
            line=10,
            end_line=10,
            column=5,
            desc="Error 1",
            rule="test_rule"
        )
        problem2 = LintProblem(
            line=10,
            end_line=10,
            column=5,
            desc="Error 2",  # Different description
            rule="test_rule"
        )

        assert problem1 == problem2

    def test_unequal_problems_different_line(self):
        """Test that problems with different lines are not equal."""
        problem1 = LintProblem(line=10, end_line=10, column=5, rule="test")
        problem2 = LintProblem(line=11, end_line=11, column=5, rule="test")

        assert problem1 != problem2

    def test_unequal_problems_different_column(self):
        """Test that problems with different columns are not equal."""
        problem1 = LintProblem(line=10, end_line=10, column=5, rule="test")
        problem2 = LintProblem(line=10, end_line=10, column=6, rule="test")

        assert problem1 != problem2

    def test_unequal_problems_different_rule(self):
        """Test that problems with different rules are not equal."""
        problem1 = LintProblem(line=10, end_line=10, column=5, rule="rule1")
        problem2 = LintProblem(line=10, end_line=10, column=5, rule="rule2")

        assert problem1 != problem2

    def test_equal_problems_with_none_column(self):
        """Test equality when column is None."""
        problem1 = LintProblem(line=10, end_line=10, rule="test")
        problem2 = LintProblem(line=10, end_line=10, rule="test")

        assert problem1 == problem2

    def test_unequal_problems_one_none_column(self):
        """Test inequality when one column is None and other is not."""
        problem1 = LintProblem(line=10, end_line=10, column=5, rule="test")
        problem2 = LintProblem(line=10, end_line=10, column=None, rule="test")

        assert problem1 != problem2


class TestLintProblemComparison:
    """Tests for __lt__ method (less than comparison)."""

    def test_compare_by_line(self):
        """Test that problems are ordered by line number."""
        problem1 = LintProblem(line=5, end_line=5, column=1)
        problem2 = LintProblem(line=10, end_line=10, column=1)

        assert problem1 < problem2
        assert not problem2 < problem1

    def test_compare_by_column_when_same_line(self):
        """Test that problems on same line are ordered by column."""
        problem1 = LintProblem(line=10, end_line=10, column=5)
        problem2 = LintProblem(line=10, end_line=10, column=15)

        assert problem1 < problem2
        assert not problem2 < problem1

    def test_compare_line_takes_precedence(self):
        """Test that line number takes precedence over column."""
        problem1 = LintProblem(line=5, end_line=5, column=20)
        problem2 = LintProblem(line=10, end_line=10, column=5)

        # problem1 is on earlier line, so it's less than problem2
        # even though it has a higher column number
        assert problem1 < problem2

    def test_sorting_multiple_problems(self):
        """Test sorting a list of problems."""
        problems = [
            LintProblem(line=15, end_line=15, column=5, desc="3rd"),
            LintProblem(line=5, end_line=5, column=10, desc="2nd"),
            LintProblem(line=5, end_line=5, column=5, desc="1st"),
            LintProblem(line=20, end_line=20, column=1, desc="4th"),
        ]

        sorted_problems = sorted(problems)

        assert sorted_problems[0].desc == "1st"
        assert sorted_problems[1].desc == "2nd"
        assert sorted_problems[2].desc == "3rd"
        assert sorted_problems[3].desc == "4th"

    def test_compare_with_none_column(self):
        """Test comparison when column is None."""
        problem1 = LintProblem(line=10, end_line=10, column=None)
        problem2 = LintProblem(line=15, end_line=15, column=None)

        assert problem1 < problem2


class TestLintProblemRepr:
    """Tests for __repr__ method."""

    def test_repr_with_all_fields(self):
        """Test string representation with all fields."""
        problem = LintProblem(
            line=10,
            end_line=10,
            column=5,
            desc="Test error",
            rule="test_rule"
        )

        repr_str = repr(problem)

        assert "10" in repr_str  # line number
        assert "5" in repr_str   # column number
        assert "Test error" in repr_str
        assert "test_rule" in repr_str

    def test_repr_without_column(self):
        """Test string representation without column."""
        problem = LintProblem(
            line=10,
            end_line=10,
            desc="Test error",
            rule="test_rule"
        )

        repr_str = repr(problem)

        assert "10" in repr_str
        assert "None" in repr_str  # column is None

    def test_repr_without_rule(self):
        """Test string representation without rule."""
        problem = LintProblem(
            line=10,
            end_line=10,
            column=5,
            desc="Test error"
        )

        repr_str = repr(problem)

        # Should not have rule in parentheses
        assert "Test error" in repr_str
        assert ")" not in repr_str.split("Test error")[1] or "(None)" not in repr_str

    def test_repr_format(self):
        """Test that repr follows expected format."""
        problem = LintProblem(
            line=42,
            end_line=42,
            column=10,
            desc="Sample problem",
            rule="sample"
        )

        repr_str = repr(problem)

        # Should be in format: line:column: message
        assert repr_str == "42:10: Sample problem (sample)"


class TestLintProblemEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_zero_line_number(self):
        """Test with line number zero."""
        problem = LintProblem(line=0, end_line=0)
        assert problem.line == 0

    def test_large_line_numbers(self):
        """Test with large line numbers."""
        problem = LintProblem(line=999999, end_line=999999)
        assert problem.line == 999999

    def test_multiline_problem(self):
        """Test problem spanning multiple lines."""
        problem = LintProblem(line=10, end_line=20)
        assert problem.line == 10
        assert problem.end_line == 20

    def test_description_with_special_characters(self):
        """Test description with special characters."""
        problem = LintProblem(
            line=1,
            end_line=1,
            desc="Error: 'single' and \"double\" quotes\n\twith\ttabs"
        )

        assert "'single'" in problem.desc
        assert '"double"' in problem.desc

    def test_long_description(self):
        """Test with very long description."""
        long_desc = "x" * 1000
        problem = LintProblem(line=1, end_line=1, desc=long_desc)

        assert len(problem.desc) == 1000

    def test_empty_description(self):
        """Test with empty description (uses default)."""
        problem = LintProblem(line=1, end_line=1, desc="")
        # Empty string was provided, so it should be used
        assert problem.desc == ""

    def test_unicode_in_description(self):
        """Test description with unicode characters."""
        problem = LintProblem(
            line=1,
            end_line=1,
            desc="Unicode: 你好 мир 🚀"
        )

        assert "你好" in problem.desc
        assert "мир" in problem.desc
        assert "🚀" in problem.desc
