import tempfile
import os
from crs_linter.linter import Linter, parse_config


def test_vulnerable_multipart_pattern_fails():
    """Test that the CVE-2026-21876 vulnerable pattern is detected (MULTIPART_PART_HEADERS)."""
    vulnerable_rule = (
        'SecRule MULTIPART_PART_HEADERS "@rx ^content-type\\\\s*:\\\\s*(.*)$" \\\n'
        '    "id:922110,\\\n'
        '    phase:2,\\\n'
        '    block,\\\n'
        '    capture,\\\n'
        '    t:none,\\\n'
        "    msg:'Multipart request with invalid charset',\\\n"
        '    chain"\n'
        '    SecRule TX:1 "@rx ^(?:charset\\\\s*=\\\\s*[\'\\"]?(?!utf-8|iso-8859-1))"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect CVE-2026-21876 pattern with MULTIPART_PART_HEADERS"
        assert "922110" in collection_problems[0].desc
        assert "MULTIPART_PART_HEADERS" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_vulnerable_request_headers_pattern_fails():
    """Test that capture from REQUEST_HEADERS with chained TX validation is detected."""
    vulnerable_rule = (
        'SecRule REQUEST_HEADERS "@rx ^x-custom-header:\\\\s*(.*)$" \\\n'
        '    "id:1001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@rx evil"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with REQUEST_HEADERS"
        assert "REQUEST_HEADERS" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_vulnerable_args_pattern_fails():
    """Test that capture from ARGS with chained TX validation is detected."""
    vulnerable_rule = (
        'SecRule ARGS "@rx (attack)" \\\n'
        '    "id:1002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq attack"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with ARGS"
        assert "ARGS" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_vulnerable_request_cookies_pattern_fails():
    """Test that capture from REQUEST_COOKIES with chained TX validation is detected."""
    vulnerable_rule = (
        'SecRule REQUEST_COOKIES "@rx (session.*)" \\\n'
        '    "id:1003,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@rx malicious"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with REQUEST_COOKIES"
        assert "REQUEST_COOKIES" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_safe_single_variable_with_chain_passes():
    """Test that capture from non-collection variables passes (e.g., REQUEST_URI)."""
    safe_rule = (
        'SecRule REQUEST_URI "@rx (attack)" \\\n'
        '    "id:2001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq attack"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag non-collection variables, but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_safe_collection_without_chain_passes():
    """Test that capture from collection without chained TX validation passes."""
    safe_rule = (
        'SecRule ARGS "@rx (attack)" \\\n'
        '    "id:2002,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        "    msg:'Attack: %{TX.1}'\""  # Uses capture but no chained rule
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag collection without chained TX validation, but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_safe_collection_chain_without_tx_reference_passes():
    """Test that collection with chain but no TX:N reference in chained rule passes."""
    safe_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:2003,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule ARGS "@rx other"'  # Chained rule doesn't use TX:N
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag chains without TX:N reference, but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_safe_collection_without_capture_passes():
    """Test that collection with chain but no capture action passes."""
    safe_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:2004,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    chain"\n'  # No capture action
        '    SecRule TX:custom_var "@eq 1"'  # Uses TX but not captured TX:N
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag without capture action, but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_vulnerable_pattern_with_tx0_fails():
    """Test that TX:0 (full match) is also detected in vulnerable pattern."""
    vulnerable_rule = (
        'SecRule ARGS "@rx (.*attack.*)" \\\n'
        '    "id:1004,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:0 "@rx suspicious"'  # TX:0 instead of TX:1
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with TX:0"
        assert "TX:0" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_vulnerable_pattern_multiple_chains_only_reports_once():
    """Test that we only report once per rule chain, not for each TX reference."""
    vulnerable_rule = (
        'SecRule ARGS "@rx (attack)" \\\n'
        '    "id:1005,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@rx evil" \\\n'
        '        "chain"\n'
        '    SecRule TX:0 "@rx bad"'  # Multiple TX references
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        # Should report the issue, but ideally only once (or at least for the first occurrence)
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with multiple chains"
    finally:
        os.unlink(temp_file)


def test_args_get_collection_fails():
    """Test that ARGS_GET (collection) is detected."""
    vulnerable_rule = (
        'SecRule ARGS_GET "@rx (test)" \\\n'
        '    "id:1006,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq test"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with ARGS_GET"
        assert "ARGS_GET" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_safe_multiple_rules_in_file():
    """Test that multiple safe rules don't trigger false positives."""
    safe_rules = '''
SecRule REQUEST_URI "@rx attack" \\
    "id:3001,\\
    phase:2,\\
    deny"

SecRule ARGS "@rx test" \\
    "id:3002,\\
    phase:2,\\
    pass,\\
    capture,\\
    msg:'Found: %{TX.1}'"

SecRule REQUEST_METHOD "@streq POST" \\
    "id:3003,\\
    phase:1,\\
    pass,\\
    chain"
    SecRule ARGS "@rx data"
'''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rules)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rules)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rules)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag safe rules, but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_safe_single_specific_key_passes():
    """Test that capture from a single specific collection key is safe (no iteration)."""
    safe_rule = (
        'SecRule REQUEST_HEADERS:Referer "@rx (attack)" \\\n'
        '    "id:4001,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq attack"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag single specific key (no iteration), but found: {collection_problems}"
    finally:
        os.unlink(temp_file)


def test_vulnerable_multiple_specific_keys_fails():
    """Test that multiple specific keys from same collection are vulnerable (iteration occurs)."""
    vulnerable_rule = (
        'SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:Cookie "@rx (attack)" \\\n'
        '    "id:1007,\\\n'
        '    phase:2,\\\n'
        '    deny,\\\n'
        '    capture,\\\n'
        '    chain"\n'
        '    SecRule TX:1 "@eq attack"'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(vulnerable_rule)
        temp_file = f.name

    try:
        parsed = parse_config(vulnerable_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=vulnerable_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) > 0, \
            "Expected to detect vulnerable pattern with multiple specific keys"
        assert "REQUEST_HEADERS" in collection_problems[0].desc
        assert "1007" in collection_problems[0].desc
    finally:
        os.unlink(temp_file)


def test_safe_intermediate_single_value_capture_passes():
    """Test rule 943110 pattern: collection capture overwritten by single-value capture is safe.

    This tests the pattern where:
    1. First rule captures from a collection (ARGS)
    2. Second chained rule captures from a single specific value (REQUEST_HEADERS:Referer)
    3. Third chained rule validates TX:1

    This is SAFE because TX:1 at validation time contains the Referer (single value),
    not the ARGS (collection). The second capture overwrites the first.
    """
    safe_rule = (
        'SecRule ARGS "@rx attack" \\\n'
        '    "id:943110,\\\n'
        '    phase:2,\\\n'
        '    block,\\\n'
        '    capture,\\\n'
        '    log,\\\n'
        '    chain"\n'
        '    SecRule REQUEST_HEADERS:Referer "@rx (https?://[^/]+)" \\\n'
        '        "capture,\\\n'
        '        chain"\n'
        '        SecRule TX:1 "!@endsWith %{request_headers.host}" \\\n'
        '            "setvar:\'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}\'"\n'
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(safe_rule)
        temp_file = f.name

    try:
        parsed = parse_config(safe_rule)
        assert parsed is not None

        linter = Linter(parsed, filename=temp_file, file_content=safe_rule)
        problems = list(linter.run_checks())

        collection_problems = [p for p in problems if p.rule == "collection_capture_chain"]
        assert len(collection_problems) == 0, \
            f"Should not flag rule 943110 pattern (intermediate single-value capture), but found: {collection_problems}"
    finally:
        os.unlink(temp_file)
