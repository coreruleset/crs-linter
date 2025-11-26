import pytest


# Base rule template for creating test rules
BASE_RULE = '''SecRule REQUEST_URI "@rx index.php" \\
    "id:{rule_id},\\
    phase:1,\\
    deny{tags}"'''


def create_rule(rule_id=1, tags=None):
    """Helper to create a rule with specified tags."""
    if tags is None:
        tag_str = ""
    elif isinstance(tags, str):
        tag_str = f",\\\n    tag:{tags}"
    else:
        tag_str = ",\\\n    " + ",\\\n    ".join(f"tag:{tag}" for tag in tags)

    return BASE_RULE.format(rule_id=rule_id, tags=tag_str)


class TestApprovedTagsBasicBehavior:
    """Test basic behavior of approved tags checking."""

    def test_no_tags_in_rule(self, run_linter):
        """Rules without tags should pass the approved tags check."""
        rule = create_rule(tags=None)
        problems = run_linter(rule, rule_type="approved_tags", tagslist=["OWASP_CRS"])

        assert len(problems) == 0, "Rules without tags should not trigger approved_tags errors"

    def test_no_tags_list_provided(self, run_linter):
        """Check should be skipped when no tags list is provided."""
        rule = create_rule(tags="any-tag-should-be-ok")
        problems = run_linter(rule, rule_type="approved_tags")

        assert len(problems) == 0, "Check should be skipped when no tags list provided"

    def test_empty_tags_list(self, run_linter):
        """All tags should fail when tags list is empty."""
        rule = create_rule(tags="OWASP_CRS")
        problems = run_linter(rule, rule_type="approved_tags", tagslist=[])

        assert len(problems) == 1, "All tags should fail with empty tags list"


@pytest.mark.parametrize("tags,approved_list,should_pass", [
    # Single approved tag
    ("OWASP_CRS", ["OWASP_CRS", "attack-sqli"], True),

    # Multiple approved tags
    (["OWASP_CRS", "attack-sqli", "paranoia-level/1"],
     ["OWASP_CRS", "attack-sqli", "paranoia-level/1"], True),

    # Single unapproved tag
    ("my-custom-tag", ["OWASP_CRS", "attack-sqli"], False),

    # Mixed approved and unapproved (2 bad tags)
    (["OWASP_CRS", "attack-sqli", "my-custom-tag", "another-bad-tag"],
     ["OWASP_CRS", "attack-sqli"], False),

    # All unapproved tags
    (["bad-tag-1", "bad-tag-2", "bad-tag-3"], ["OWASP_CRS"], False),

    # Tags with special characters
    (["paranoia-level/1", "capec/1000/152/137", "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"],
     ["paranoia-level/1", "capec/1000/152/137", "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"], True),

    # Case sensitivity - lowercase vs uppercase
    ("owasp_crs", ["OWASP_CRS"], False),

    # Duplicate approved tags
    (["OWASP_CRS", "OWASP_CRS"], ["OWASP_CRS"], True),
])
def test_approved_tags_validation(run_linter, tags, approved_list, should_pass):
    """Test various tag validation scenarios using parametrization."""
    rule = create_rule(tags=tags)
    problems = run_linter(rule, rule_type="approved_tags", tagslist=approved_list)

    if should_pass:
        assert len(problems) == 0, f"Tags {tags} should pass with approved list {approved_list}"
    else:
        assert len(problems) > 0, f"Tags {tags} should fail with approved list {approved_list}"


@pytest.mark.parametrize("tags,approved_list,expected_bad_tags", [
    # Single unapproved tag
    ("my-custom-tag", ["OWASP_CRS"], ["my-custom-tag"]),

    # Two unapproved tags
    (["OWASP_CRS", "my-custom-tag", "another-bad-tag"],
     ["OWASP_CRS"], ["my-custom-tag", "another-bad-tag"]),

    # All three tags unapproved
    (["bad-tag-1", "bad-tag-2", "bad-tag-3"],
     ["OWASP_CRS"], ["bad-tag-1", "bad-tag-2", "bad-tag-3"]),

    # Case sensitivity check
    ("owasp_crs", ["OWASP_CRS"], ["owasp_crs"]),
])
def test_unapproved_tags_error_messages(run_linter, tags, approved_list, expected_bad_tags):
    """Test that error messages contain the correct unapproved tags."""
    rule = create_rule(tags=tags)
    problems = run_linter(rule, rule_type="approved_tags", tagslist=approved_list)

    assert len(problems) == len(expected_bad_tags), \
        f"Should catch exactly {len(expected_bad_tags)} unapproved tags"

    error_messages = [p.desc for p in problems]
    for bad_tag in expected_bad_tags:
        assert any(bad_tag in msg for msg in error_messages), \
            f"Error messages should mention '{bad_tag}'"


def test_multiple_rules_with_tags(run_linter):
    """Test that approved tags check works across multiple rules."""
    rule = '''SecRule REQUEST_URI "@rx index.php" \\
    "id:1,\\
    phase:1,\\
    deny,\\
    tag:good-tag"

SecRule REQUEST_URI "@rx admin.php" \\
    "id:2,\\
    phase:1,\\
    deny,\\
    tag:bad-tag"'''

    problems = run_linter(rule, rule_type="approved_tags", tagslist=["good-tag"])

    assert len(problems) == 1, "Should catch unapproved tag in second rule"
    assert "bad-tag" in problems[0].desc, "Error should mention bad-tag"


@pytest.mark.parametrize("rule_tags,count", [
    (["tag:OWASP_CRS"], 1),
    (["tag:OWASP_CRS", "tag:attack-sqli"], 2),
    (["tag:OWASP_CRS", "tag:attack-sqli", "tag:paranoia-level/1"], 3),
    (["tag:OWASP_CRS", "tag:OWASP_CRS"], 2),  # Duplicate
])
def test_tag_count_parsing(parse_rule, rule_tags, count):
    """Test that the parser correctly extracts all tags from a rule."""
    tags_str = ",\\\n    ".join(rule_tags)
    rule = f'''SecRule REQUEST_URI "@rx index.php" \\
    "id:1,\\
    phase:1,\\
    deny,\\
    {tags_str}"'''

    parsed = parse_rule(rule)

    # Count tags in parsed actions
    tag_actions = [a for a in parsed[0]["actions"] if a["act_name"] == "tag"]
    assert len(tag_actions) == count, f"Should find {count} tag actions"
