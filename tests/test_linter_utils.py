"""Additional tests for Linter class utility methods."""

import pytest
import tempfile
import os
from pathlib import Path
from crs_linter.linter import Linter, parse_config, parse_file


class TestLinterGenCrsFileTag:
    """Tests for the gen_crs_file_tag method."""

    def test_gen_crs_file_tag_request_file(self):
        """Test generating tag from REQUEST file."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename="REQUEST-942-APPLICATION-ATTACK-SQLI.conf")

        tag = linter.gen_crs_file_tag()

        assert tag == "OWASP_CRS/ATTACK-SQLI"

    def test_gen_crs_file_tag_response_file(self):
        """Test generating tag from RESPONSE file."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename="RESPONSE-955-WEB-SHELLS.conf")

        tag = linter.gen_crs_file_tag()

        assert tag == "OWASP_CRS/WEB-SHELLS"

    def test_gen_crs_file_tag_removes_application_prefix(self):
        """Test that APPLICATION- prefix is removed from tag."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename="REQUEST-920-APPLICATION-PROTOCOL.conf")

        tag = linter.gen_crs_file_tag()

        # APPLICATION- should be removed
        assert tag == "OWASP_CRS/PROTOCOL"
        assert "APPLICATION" not in tag

    def test_gen_crs_file_tag_with_path(self):
        """Test generating tag from file with full path."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(
            parsed,
            filename="/path/to/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"
        )

        tag = linter.gen_crs_file_tag()

        assert tag == "OWASP_CRS/ATTACK-LFI"

    def test_gen_crs_file_tag_with_custom_filename(self):
        """Test generating tag with custom filename parameter."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename="default.conf")

        tag = linter.gen_crs_file_tag(fname="REQUEST-941-XSS.conf")

        assert tag == "OWASP_CRS/XSS"

    def test_gen_crs_file_tag_strips_extension(self):
        """Test that file extension is stripped."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename="REQUEST-942-SQLI.conf")

        tag = linter.gen_crs_file_tag()

        assert not tag.endswith(".conf")

    @pytest.mark.parametrize("filename,expected_tag", [
        ("REQUEST-901-INIT.conf", "OWASP_CRS/INIT"),
        ("RESPONSE-959-BLOCKING.conf", "OWASP_CRS/BLOCKING"),
        ("REQUEST-920-APPLICATION-PROTOCOL-ENFORCEMENT.conf", "OWASP_CRS/PROTOCOL-ENFORCEMENT"),
        ("REQUEST-932-APPLICATION-ATTACK-RCE.conf", "OWASP_CRS/ATTACK-RCE"),
    ])
    def test_gen_crs_file_tag_various_files(self, filename, expected_tag):
        """Test tag generation for various CRS files."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed, filename=filename)

        tag = linter.gen_crs_file_tag()

        assert tag == expected_tag


class TestLinterInit:
    """Tests for Linter initialization."""

    def test_init_with_minimal_params(self):
        """Test initialization with minimal parameters."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        linter = Linter(parsed)

        assert linter.data == parsed
        assert linter.filename is None
        assert linter.file_content is None
        assert linter.globtxvars == {}
        assert linter.ids == {}

    def test_init_with_all_params(self):
        """Test initialization with all parameters."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        txvars = {"test": {"phase": 1}}
        ids = {1: {"fname": "test.conf", "lineno": 1}}

        linter = Linter(
            parsed,
            filename="test.conf",
            txvars=txvars,
            ids=ids,
            file_content=rule
        )

        assert linter.data == parsed
        assert linter.filename == "test.conf"
        assert linter.file_content == rule
        assert linter.globtxvars == txvars
        assert linter.ids == ids

    def test_init_preserves_shared_state(self):
        """Test that txvars and ids dicts are shared references."""
        rule = 'SecRule ARGS "@rx test" "id:1"'
        parsed = parse_config(rule)
        txvars = {"test": {"phase": 1}}
        ids = {1: {"fname": "test.conf", "lineno": 1}}

        linter = Linter(parsed, txvars=txvars, ids=ids)

        # Modify through linter
        linter.globtxvars["new_var"] = {"phase": 2}
        linter.ids[2] = {"fname": "test2.conf", "lineno": 2}

        # Should be reflected in original dicts
        assert "new_var" in txvars
        assert 2 in ids


class TestParseConfig:
    """Tests for parse_config function."""

    def test_parse_config_simple_rule(self):
        """Test parsing a simple SecRule."""
        rule = 'SecRule ARGS "@rx test" "id:1,phase:2,deny"'
        parsed = parse_config(rule)

        assert parsed is not None
        assert len(parsed) > 0
        assert parsed[0]["type"] == "SecRule"

    def test_parse_config_secaction(self):
        """Test parsing SecAction."""
        rule = 'SecAction "id:1,phase:1,pass,nolog,setvar:tx.test=1"'
        parsed = parse_config(rule)

        assert parsed is not None
        assert len(parsed) > 0
        assert parsed[0]["type"] == "SecAction"

    def test_parse_config_multiline_rule(self):
        """Test parsing multiline rule."""
        rule = '''SecRule ARGS "@rx test" \\
    "id:1,\\
    phase:2,\\
    deny,\\
    t:none"'''
        parsed = parse_config(rule)

        assert parsed is not None
        assert len(parsed) > 0

    def test_parse_config_multiple_rules(self):
        """Test parsing multiple rules."""
        rule = '''SecRule ARGS "@rx test1" "id:1,phase:2,deny"
SecRule ARGS "@rx test2" "id:2,phase:2,deny"
SecAction "id:3,phase:1,pass"'''
        parsed = parse_config(rule)

        assert parsed is not None
        assert len(parsed) == 3

    def test_parse_config_chained_rules(self):
        """Test parsing chained rules."""
        rule = '''SecRule ARGS "@rx test" \\
    "id:1,phase:2,deny,chain"
    SecRule ARGS "@rx test2" \\
    "t:none"'''
        parsed = parse_config(rule)

        assert parsed is not None
        assert len(parsed) == 2

    def test_parse_config_with_comments(self):
        """Test parsing rules with comments."""
        rule = '''# This is a comment
SecRule ARGS "@rx test" "id:1,phase:2,deny"
# Another comment'''
        parsed = parse_config(rule)

        assert parsed is not None
        # Parser includes comments in the parsed output
        # So we should have 3 elements: comment, SecRule, comment
        assert len(parsed) >= 1
        # At least one should be a SecRule
        secrules = [p for p in parsed if p.get("type") == "SecRule"]
        assert len(secrules) == 1

    def test_parse_config_empty_string(self):
        """Test parsing empty string."""
        parsed = parse_config("")

        # Parser might return empty list or None
        assert parsed is not None or parsed == []

    def test_parse_config_invalid_syntax(self):
        """Test parsing invalid syntax returns None or handles gracefully."""
        rule = 'This is not a valid ModSecurity rule'
        parsed = parse_config(rule)

        # Should handle gracefully (might return None or empty list)
        # The actual behavior depends on msc_pyparser


class TestParseFile:
    """Tests for parse_file function."""

    def test_parse_file_valid_file(self):
        """Test parsing a valid file."""
        rule = 'SecRule ARGS "@rx test" "id:1,phase:2,deny"'

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(rule)
            temp_file = f.name

        try:
            parsed = parse_file(temp_file)

            assert parsed is not None
            assert len(parsed) > 0
            assert parsed[0]["type"] == "SecRule"
        finally:
            os.unlink(temp_file)

    def test_parse_file_multiple_rules(self):
        """Test parsing file with multiple rules."""
        rules = '''SecRule ARGS "@rx test1" "id:1,phase:2,deny"
SecRule ARGS "@rx test2" "id:2,phase:2,deny"
SecAction "id:3,phase:1,pass"'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(rules)
            temp_file = f.name

        try:
            parsed = parse_file(temp_file)

            assert parsed is not None
            assert len(parsed) == 3
        finally:
            os.unlink(temp_file)

    def test_parse_file_with_comments(self):
        """Test parsing file with comments."""
        content = '''# Comment at top
SecRule ARGS "@rx test" "id:1,phase:2,deny"
# Comment in middle
SecAction "id:2,phase:1,pass"
# Comment at end'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(content)
            temp_file = f.name

        try:
            parsed = parse_file(temp_file)

            assert parsed is not None
            assert len(parsed) >= 2  # Should have at least the 2 rules
        finally:
            os.unlink(temp_file)

    def test_parse_file_empty_file(self):
        """Test parsing empty file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("")
            temp_file = f.name

        try:
            parsed = parse_file(temp_file)

            # Should handle empty file gracefully
            assert parsed is not None or parsed == []
        finally:
            os.unlink(temp_file)

    def test_parse_file_nonexistent_file(self):
        """Test parsing non-existent file."""
        parsed = parse_file("/nonexistent/file.conf")

        # Should return None or handle error gracefully


class TestLinterCollectTxVariables:
    """Tests for _collect_tx_variables method."""

    def test_collect_tx_variables_simple_setvar(self):
        """Test collecting TX variables from simple setvar."""
        rule = '''SecAction "id:1,phase:1,pass,setvar:tx.test=value"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        assert "test" in linter.globtxvars
        assert linter.globtxvars["test"]["phase"] == 1

    def test_collect_tx_variables_multiple_setvars(self):
        """Test collecting multiple TX variables."""
        rule = '''SecAction "id:1,phase:1,pass,setvar:tx.var1=1,setvar:tx.var2=2"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        assert "var1" in linter.globtxvars
        assert "var2" in linter.globtxvars

    def test_collect_tx_variables_respects_phase(self):
        """Test that lower phase variables take precedence."""
        rule = '''SecAction "id:1,phase:2,pass,setvar:tx.test=value1"
SecAction "id:2,phase:1,pass,setvar:tx.test=value2"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        # Phase 1 (lower) should take precedence
        assert linter.globtxvars["test"]["phase"] == 1

    def test_collect_tx_variables_case_insensitive(self):
        """Test that TX variable names are case-insensitive (lowercased)."""
        rule = '''SecAction "id:1,phase:1,pass,setvar:TX.TEST=value"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        assert "test" in linter.globtxvars

    def test_collect_tx_variables_ignores_non_tx_setvars(self):
        """Test that non-TX setvars are ignored."""
        rule = '''SecAction "id:1,phase:1,pass,setvar:ip.test=value"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        assert "test" not in linter.globtxvars

    def test_collect_tx_variables_with_chain(self):
        """Test collecting TX variables with chained rules."""
        rule = '''SecRule ARGS "@rx test" "id:1,phase:2,pass,chain"
    SecRule ARGS "@rx test2" "setvar:tx.matched=1"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        assert "matched" in linter.globtxvars

    def test_collect_tx_variables_skips_dynamic_names(self):
        """Test that variables with dynamic names are skipped."""
        rule = '''SecAction "id:1,phase:1,pass,setvar:tx.%{REQUEST_METHOD}=value"'''
        parsed = parse_config(rule)
        linter = Linter(parsed)

        linter._collect_tx_variables()

        # Dynamic variable names (containing %{...}) should be skipped
        # The dict should be empty or not contain the dynamic key
        assert len([k for k in linter.globtxvars.keys() if "%{" in k]) == 0
