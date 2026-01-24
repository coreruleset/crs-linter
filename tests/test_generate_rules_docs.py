"""Tests for generate_rules_docs.py module."""

import pytest
from generate_rules_docs import format_code_blocks, extract_rule_docs, format_rule_docs


class TestFormatCodeBlocks:
    """Tests for the format_code_blocks function."""

    def test_basic_secrule_detection(self):
        """Test that SecRule directives are detected and wrapped in code blocks."""
        docstring = """Check for valid rules.

Example:

    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\
        "id:920161"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert 'SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\' in result
        assert result.count("```apache") == 1
        assert result.count("```") == 2  # Opening and closing

    def test_comment_line_starts_code_block(self):
        """Test that standalone comment lines start code blocks."""
        docstring = """Check for comments.

Example:

    # Rule missing severity action
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^\\d+$" \\
        "id:920161"
"""
        result = format_code_blocks(docstring)
        assert "```apache\n# Rule missing severity action" in result
        assert "    # Rule missing severity action" not in result  # Should not be outside block

    def test_comment_between_code_blocks(self):
        """Test that comments between code examples are handled correctly."""
        docstring = """Multiple examples.

Example 1:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"

    # Second example
    SecRule REQUEST_URI "@rx test2" \\
        "id:2"
"""
        result = format_code_blocks(docstring)
        # Blank line between rules means two separate code blocks
        assert result.count("```apache") == 2
        assert "# Second example" in result
        assert "    # Second example" not in result  # Not indented outside block

    def test_multiple_code_blocks(self):
        """Test multiple separate code blocks are created correctly."""
        docstring = """Multiple examples.

Example 1:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"

Regular text here.

Example 2:

    SecRule REQUEST_URI "@rx test2" \\
        "id:2"
"""
        result = format_code_blocks(docstring)
        assert result.count("```apache") == 2
        assert result.count("```") == 4  # Two opening, two closing
        assert "Regular text here." in result

    def test_code_continuation_with_quotes(self):
        """Test that lines with quotes are recognized as code continuation."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1,\\
        phase:1,\\
        log"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert '"id:1,\\' in result
        assert 'phase:1,\\' in result
        assert 'log"' in result

    def test_code_continuation_with_backslash(self):
        """Test that lines with backslash are recognized as code continuation."""
        docstring = """Example:

    SecRule REQUEST_URI \\
        "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert 'SecRule REQUEST_URI \\' in result
        assert '"@rx test" \\' in result

    def test_secaction_directive(self):
        """Test that SecAction directives are detected."""
        docstring = """Example:

    SecAction \\
        "id:900000,\\
        phase:1"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert "SecAction" in result

    def test_secruleupdatetargetbyid_directive(self):
        """Test that SecRuleUpdateTargetById directives are detected."""
        docstring = """Example:

    SecRuleUpdateTargetById 920100 "!ARGS:test"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert "SecRuleUpdateTargetById" in result

    def test_secruleremovebyid_directive(self):
        """Test that SecRuleRemoveById directives are detected."""
        docstring = """Example:

    SecRuleRemoveById 920100
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert "SecRuleRemoveById" in result

    def test_blank_lines_close_code_blocks(self):
        """Test that blank lines close code blocks."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"

    SecRule REQUEST_URI "@rx test2" \\
        "id:2"
"""
        result = format_code_blocks(docstring)
        # Should create two separate code blocks due to blank line
        assert result.count("```apache") == 2

    def test_example_header_detection(self):
        """Test that 'Example:' headers are detected and handled."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        assert "Example:" in result
        assert "```apache" in result

    def test_lowercase_example_header(self):
        """Test that 'example:' (lowercase) headers are detected."""
        docstring = """example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        assert "example:" in result
        assert "```apache" in result

    def test_no_code_blocks_for_plain_text(self):
        """Test that plain text without code directives is not wrapped."""
        docstring = """Just plain documentation.

This is regular text without any code.
No SecRule directives here.
"""
        result = format_code_blocks(docstring)
        assert "```apache" not in result
        assert "```" not in result

    def test_indented_text_without_directives(self):
        """Test that indented text without directives is not wrapped."""
        docstring = """Some text:

    This is just indented text
    without any ModSecurity directives
    or code markers
"""
        result = format_code_blocks(docstring)
        assert "```apache" not in result

    def test_code_block_closes_at_end(self):
        """Test that code blocks are properly closed at the end of docstring."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        # Should have closing backticks
        assert result.strip().endswith("```")

    def test_multiple_example_sections(self):
        """Test handling of multiple Example: sections."""
        docstring = """Example 1:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"

Example 2:

    SecRule REQUEST_URI "@rx test2" \\
        "id:2"
"""
        result = format_code_blocks(docstring)
        assert result.count("Example") == 2
        assert result.count("```apache") == 2

    def test_indentation_is_removed(self):
        """Test that 4-space docstring indentation is removed from code."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        # The SecRule line should not start with spaces in the code block
        lines = result.split('\n')
        in_code_block = False
        for line in lines:
            if line.strip() == '```apache':
                in_code_block = True
                continue
            if in_code_block and line.strip() == '```':
                break
            if in_code_block and line.startswith('SecRule'):
                # Should not have leading spaces
                assert line == 'SecRule REQUEST_URI "@rx test" \\'
                break

    def test_edge_case_empty_docstring(self):
        """Test handling of empty docstring."""
        docstring = ""
        result = format_code_blocks(docstring)
        assert result == ""

    def test_edge_case_only_whitespace(self):
        """Test handling of docstring with only whitespace."""
        docstring = "   \n\n   "
        result = format_code_blocks(docstring)
        assert "```" not in result

    def test_comment_in_middle_of_rule(self):
        """Test that comments in the middle of a rule stay in code block."""
        docstring = """Example:

    SecRule REQUEST_URI "@rx test" \\
        # This is a comment inside the rule
        "id:1"
"""
        result = format_code_blocks(docstring)
        assert "```apache" in result
        assert "# This is a comment inside the rule" in result
        # Should be one continuous code block
        assert result.count("```apache") == 1

    def test_lookahead_finds_code(self):
        """Test that lookahead properly detects code after Example header."""
        docstring = """Example:

    Some descriptive text here
    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
        result = format_code_blocks(docstring)
        # Should create a code block when SecRule is found in lookahead
        assert "```apache" in result

    def test_lookahead_no_code_found(self):
        """Test that no code block is created when lookahead finds no code."""
        docstring = """Example:

    Just some regular indented text
    with no code directives at all
    nothing to see here
"""
        result = format_code_blocks(docstring)
        # Should not create code blocks
        assert "```apache" not in result


class TestExtractRuleDocs:
    """Tests for the extract_rule_docs function."""

    def test_extracts_rule_classes(self):
        """Test that rule documentation is extracted from rule classes."""
        docs = extract_rule_docs()
        assert len(docs) > 0
        assert all('name' in doc for doc in docs)
        assert all('module_name' in doc for doc in docs)
        assert all('docstring' in doc for doc in docs)

    def test_docs_have_non_empty_docstrings(self):
        """Test that all extracted docs have non-empty docstrings."""
        docs = extract_rule_docs()
        assert all(doc['docstring'] for doc in docs)

    def test_docs_are_sorted(self):
        """Test that docs are returned in sorted order by module name."""
        docs = extract_rule_docs()
        module_names = [doc['module_name'] for doc in docs]
        # Should be in alphabetical order since we use sorted(rules_dir.glob())
        assert module_names == sorted(module_names)


class TestFormatRuleDocs:
    """Tests for the format_rule_docs function."""

    def test_formats_with_headings(self):
        """Test that formatted docs include proper headings."""
        docs = [
            {
                'name': 'TestRule',
                'module_name': 'test_rule',
                'docstring': 'Test docstring'
            }
        ]
        result = format_rule_docs(docs)
        assert '# 📖 Linting Rules Reference' in result
        assert '## TestRule' in result

    def test_includes_source_reference(self):
        """Test that source file reference is included."""
        docs = [
            {
                'name': 'TestRule',
                'module_name': 'test_rule',
                'docstring': 'Test docstring'
            }
        ]
        result = format_rule_docs(docs)
        assert '**Source:** `src/crs_linter/rules/test_rule.py`' in result

    def test_includes_update_instructions(self):
        """Test that update instructions are included."""
        docs = [
            {
                'name': 'TestRule',
                'module_name': 'test_rule',
                'docstring': 'Test docstring'
            }
        ]
        result = format_rule_docs(docs)
        assert 'To update this documentation' in result
        assert 'python generate_rules_docs.py' in result

    def test_formats_multiple_rules(self):
        """Test formatting multiple rules."""
        docs = [
            {
                'name': 'TestRule1',
                'module_name': 'test_rule_1',
                'docstring': 'First test docstring'
            },
            {
                'name': 'TestRule2',
                'module_name': 'test_rule_2',
                'docstring': 'Second test docstring'
            }
        ]
        result = format_rule_docs(docs)
        assert '## TestRule1' in result
        assert '## TestRule2' in result
        assert 'First test docstring' in result
        assert 'Second test docstring' in result

    def test_applies_code_block_formatting(self):
        """Test that code blocks are formatted in docstrings."""
        docs = [
            {
                'name': 'TestRule',
                'module_name': 'test_rule',
                'docstring': """Test rule.

Example:

    SecRule REQUEST_URI "@rx test" \\
        "id:1"
"""
            }
        ]
        result = format_rule_docs(docs)
        assert '```apache' in result
        assert 'SecRule REQUEST_URI' in result
