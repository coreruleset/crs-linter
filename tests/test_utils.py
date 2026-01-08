"""Tests for utility functions."""

import pytest
import tempfile
from pathlib import Path
from crs_linter.utils import (
    get_id,
    remove_comments,
    parse_version_from_commit_message,
    parse_version_from_branch_name,
    generate_version_string,
    parse_version_from_latest_tag,
)


class TestGetId:
    """Tests for the get_id function."""

    def test_get_id_returns_id_from_actions(self):
        """Test that get_id extracts the ID from actions."""
        actions = [
            {"act_name": "phase", "act_arg": "1"},
            {"act_name": "id", "act_arg": "942100"},
            {"act_name": "pass", "act_arg": ""}
        ]
        assert get_id(actions) == 942100

    def test_get_id_returns_zero_when_no_id(self):
        """Test that get_id returns 0 when no ID is present."""
        actions = [
            {"act_name": "phase", "act_arg": "1"},
            {"act_name": "pass", "act_arg": ""}
        ]
        assert get_id(actions) == 0

    def test_get_id_with_empty_actions(self):
        """Test that get_id handles empty actions list."""
        actions = []
        assert get_id(actions) == 0

    def test_get_id_returns_first_id_when_multiple(self):
        """Test that get_id returns the first ID when multiple are present."""
        actions = [
            {"act_name": "id", "act_arg": "100"},
            {"act_name": "phase", "act_arg": "1"},
            {"act_name": "id", "act_arg": "200"}
        ]
        assert get_id(actions) == 100

    @pytest.mark.parametrize("id_value,expected", [
        ("1", 1),
        ("942100", 942100),
        ("999999", 999999),
        ("0", 0),
    ])
    def test_get_id_with_various_values(self, id_value, expected):
        """Test get_id with various ID values."""
        actions = [{"act_name": "id", "act_arg": id_value}]
        assert get_id(actions) == expected


class TestRemoveComments:
    """Tests for the remove_comments function."""

    def test_remove_comments_from_secrule(self):
        """Test removing comments from SecRule directive."""
        data = """# Some comment
#SecRule ARGS "@rx attack" \\
#    "id:1,\\
#    phase:1,\\
#    deny"

# Another comment"""

        result = remove_comments(data)

        assert "SecRule ARGS" in result
        assert result.count("#SecRule") == 0
        # First and last comments should remain
        lines = result.split("\n")
        assert lines[0] == "# Some comment"
        assert lines[-1] == "# Another comment"

    def test_remove_comments_from_secaction(self):
        """Test removing comments from SecAction directive."""
        data = """#SecAction \\
#    "id:900000,\\
#    phase:1,\\
#    pass"
"""

        result = remove_comments(data)

        assert "SecAction" in result
        assert "#SecAction" not in result

    def test_remove_comments_with_spaces(self):
        """Test removing comments with spaces after hash."""
        data = """# SecRule ARGS "@rx attack" \\
#    "id:1,\\
#    phase:1,\\
#    deny"
"""

        result = remove_comments(data)

        assert " SecRule ARGS" in result

    def test_remove_comments_stops_at_empty_line(self):
        """Test that comment removal stops at empty line and can restart."""
        data = """#SecRule ARGS "@rx attack" \\
#    "id:1,\\
#    phase:1"

#SecRule ARGS "@rx other" \\
#    "id:2"
"""

        result = remove_comments(data)

        # Both SecRules should have comments removed
        # (the function restarts comment removal after empty line when it encounters another #SecRule)
        assert "SecRule ARGS \"@rx attack\"" in result
        assert "SecRule ARGS \"@rx other\"" in result
        # Both should have had their leading # removed
        assert result.count("#SecRule") == 0

    def test_remove_comments_preserves_other_comments(self):
        """Test that other comments are preserved."""
        data = """# This is a regular comment
SecRule ARGS "@rx foo" "id:1"
# Another regular comment
"""

        result = remove_comments(data)

        assert "# This is a regular comment" in result
        assert "# Another regular comment" in result

    def test_remove_comments_case_insensitive(self):
        """Test that comment removal is case insensitive."""
        data = """#secrule ARGS "@rx attack" \\
#    "id:1"

#SECACTION "id:2"
"""

        result = remove_comments(data)

        assert "secrule ARGS" in result
        assert "SECACTION" in result

    def test_remove_comments_empty_string(self):
        """Test remove_comments with empty string."""
        result = remove_comments("")
        assert result == ""

    def test_remove_comments_only_hash_line_stops_removal(self):
        """Test that a line with only # stops comment removal."""
        data = """#SecRule ARGS "@rx attack" \\
#    "id:1,\\
#    phase:1"
#
# This should not be uncommented
"""

        result = remove_comments(data)

        assert "SecRule ARGS" in result
        assert "# This should not be uncommented" in result


class TestParseVersionFromCommitMessage:
    """Tests for parse_version_from_commit_message function."""

    def test_parse_version_from_standard_release_message(self):
        """Test parsing version from standard release commit message."""
        message = "chore: release v1.2.3"
        version = parse_version_from_commit_message(message)

        assert version is not None
        assert str(version) == "1.2.3"

    def test_parse_version_with_extra_text(self):
        """Test parsing version with additional text in message."""
        message = "release v4.5.0\n\nThis is a great release!"
        version = parse_version_from_commit_message(message)

        assert version is not None
        assert str(version) == "4.5.0"

    def test_parse_version_case_insensitive(self):
        """Test that parsing is case insensitive."""
        message = "RELEASE v2.3.4"
        version = parse_version_from_commit_message(message)

        assert version is not None
        assert str(version) == "2.3.4"

    def test_parse_version_ignores_post_release(self):
        """Test that post-release commits are ignored."""
        message = "chore: post release v1.2.3"
        version = parse_version_from_commit_message(message)

        assert version is None

    def test_parse_version_returns_none_for_empty_message(self):
        """Test that empty message returns None."""
        assert parse_version_from_commit_message("") is None
        assert parse_version_from_commit_message(None) is None

    def test_parse_version_returns_none_for_non_release_message(self):
        """Test that non-release messages return None."""
        message = "fix: bug in rule 942100"
        version = parse_version_from_commit_message(message)

        assert version is None

    @pytest.mark.parametrize("message,expected_version", [
        ("release v1.0.0", "1.0.0"),
        ("chore: release v10.20.30", "10.20.30"),
        ("Release v0.1.0", "0.1.0"),
        ("RELEASE v99.99.99", "99.99.99"),
    ])
    def test_parse_version_various_formats(self, message, expected_version):
        """Test parsing various version formats."""
        version = parse_version_from_commit_message(message)
        assert str(version) == expected_version


class TestParseVersionFromBranchName:
    """Tests for parse_version_from_branch_name function."""

    def test_parse_version_from_release_branch(self):
        """Test parsing version from release branch name."""
        branch = "release/v1.2.3"
        version = parse_version_from_branch_name(branch)

        assert version is not None
        assert str(version) == "1.2.3"

    def test_parse_version_with_refs_prefix(self):
        """Test parsing with full ref path."""
        branch = "refs/heads/release/v4.5.0"
        version = parse_version_from_branch_name(branch)

        assert version is not None
        assert str(version) == "4.5.0"

    def test_parse_version_ignores_post_release_branch(self):
        """Test that post-release branches are ignored."""
        branch = "post-release/v1.2.3"
        version = parse_version_from_branch_name(branch)

        assert version is None

    def test_parse_version_returns_none_for_empty_branch(self):
        """Test that empty branch returns None."""
        assert parse_version_from_branch_name("") is None
        assert parse_version_from_branch_name(None) is None

    def test_parse_version_returns_none_for_non_release_branch(self):
        """Test that non-release branches return None."""
        branch = "feature/new-rule"
        version = parse_version_from_branch_name(branch)

        assert version is None

    @pytest.mark.parametrize("branch,expected_version", [
        ("release/v1.0.0", "1.0.0"),
        ("release/v10.20.30", "10.20.30"),
        ("release/v0.1.0", "0.1.0"),
        ("origin/release/v2.3.4", "2.3.4"),
    ])
    def test_parse_version_various_branch_formats(self, branch, expected_version):
        """Test parsing various branch name formats."""
        version = parse_version_from_branch_name(branch)
        assert str(version) == expected_version


class TestGenerateVersionString:
    """Tests for generate_version_string function."""

    def test_generate_version_from_commit_message(self):
        """Test generating version string from commit message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            # Initialize a git repo
            import subprocess
            subprocess.run(["git", "init"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True)
            # Create initial commit with tag
            (directory / "test.txt").write_text("test")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=directory, capture_output=True)
            subprocess.run(["git", "tag", "v1.0.0"], cwd=directory, capture_output=True)

            version_string = generate_version_string(
                directory, None, "release v2.3.4"
            )

            assert version_string == "OWASP_CRS/2.3.4"

    def test_generate_version_from_branch_name(self):
        """Test generating version string from branch name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            # Initialize a git repo
            import subprocess
            subprocess.run(["git", "init"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True)
            (directory / "test.txt").write_text("test")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=directory, capture_output=True)
            subprocess.run(["git", "tag", "v1.0.0"], cwd=directory, capture_output=True)

            version_string = generate_version_string(
                directory, "release/v3.5.0", None
            )

            assert version_string == "OWASP_CRS/3.5.0"

    def test_generate_version_raises_for_nonexistent_directory(self):
        """Test that generate_version_string raises for non-existent directory."""
        directory = Path("/nonexistent/path")

        with pytest.raises(ValueError, match="does not exist"):
            generate_version_string(directory, None, None)

    def test_generate_version_prefers_commit_message_over_branch(self):
        """Test that commit message takes precedence over branch name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            # Initialize a git repo
            import subprocess
            subprocess.run(["git", "init"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=directory, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True)
            (directory / "test.txt").write_text("test")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=directory, capture_output=True)
            subprocess.run(["git", "tag", "v1.0.0"], cwd=directory, capture_output=True)

            version_string = generate_version_string(
                directory,
                "release/v2.0.0",  # Branch says v2.0.0
                "release v3.0.0"   # Commit message says v3.0.0
            )

            # Should prefer commit message
            assert version_string == "OWASP_CRS/3.0.0"


class TestParseVersionFromLatestTag:
    """Tests for parse_version_from_latest_tag function."""

    def test_parse_version_filters_by_major_version(self):
        """
        Test that parse_version_from_latest_tag filters tags by major version.

        This is the critical test for the bug fix: when working on a 3.x branch,
        we should get the latest 3.x tag, not a newer 4.x tag from a different
        major version line.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            import subprocess

            # Initialize a git repo
            subprocess.run(["git", "init"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=directory, capture_output=True, check=True)

            # Create v3.3.0 tag on initial commit
            (directory / "test.txt").write_text("v3.3.0")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v3.3.0", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v3.3.0"], cwd=directory, capture_output=True, check=True)

            # Create v3.3.8 tag
            (directory / "test.txt").write_text("v3.3.8")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v3.3.8", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v3.3.8"], cwd=directory, capture_output=True, check=True)

            # Save the 3.x branch point
            result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=directory, capture_output=True, check=True, text=True)
            branch_3x_sha = result.stdout.strip()

            # Create a new branch for 4.x development
            subprocess.run(["git", "checkout", "-b", "v4.x-dev"], cwd=directory, capture_output=True, check=True)

            # Create v4.0.0 tag
            (directory / "test.txt").write_text("v4.0.0")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v4.0.0", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v4.0.0"], cwd=directory, capture_output=True, check=True)

            # Create v4.5.0 tag (this is the most recent tag globally)
            (directory / "test.txt").write_text("v4.5.0")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v4.5.0", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v4.5.0"], cwd=directory, capture_output=True, check=True)

            # Go back to the 3.x branch
            subprocess.run(["git", "checkout", "-b", "v3.x-maintenance", branch_3x_sha], cwd=directory, capture_output=True, check=True)

            # Create a commit on the 3.x branch (simulating a maintenance branch)
            (directory / "maintenance.txt").write_text("3.x maintenance")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "3.x maintenance work", "--no-verify"], cwd=directory, capture_output=True, check=True)

            # Now test: we're on a 3.x branch, so we should get v3.3.8, not v4.5.0
            version = parse_version_from_latest_tag(directory)

            assert str(version) == "3.3.8", f"Expected 3.3.8 but got {version}"

    def test_generate_version_with_major_version_filtering(self):
        """
        Test that generate_version_string produces correct -dev version
        when tags from different major versions exist.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            import subprocess

            # Initialize a git repo
            subprocess.run(["git", "init"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=directory, capture_output=True, check=True)

            # Create v3.3.8 tag
            (directory / "test.txt").write_text("v3.3.8")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v3.3.8", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v3.3.8"], cwd=directory, capture_output=True, check=True)

            # Save the 3.x branch point
            result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=directory, capture_output=True, check=True, text=True)
            branch_3x_sha = result.stdout.strip()

            # Create a new branch for 4.x development
            subprocess.run(["git", "checkout", "-b", "v4.x-dev"], cwd=directory, capture_output=True, check=True)

            # Create v4.5.0 tag (this is the most recent tag globally)
            (directory / "test.txt").write_text("v4.5.0")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "v4.5.0", "--no-verify"], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "tag", "v4.5.0"], cwd=directory, capture_output=True, check=True)

            # Go back to the 3.x branch
            subprocess.run(["git", "checkout", "-b", "fix-942360", branch_3x_sha], cwd=directory, capture_output=True, check=True)

            # Create a commit on the 3.x branch
            (directory / "fix.txt").write_text("fix")
            subprocess.run(["git", "add", "."], cwd=directory, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "fix: issue 942360", "--no-verify"], cwd=directory, capture_output=True, check=True)

            # Now test: we're on a 3.x branch, so we should get 3.4.0-dev, not 4.6.0-dev
            version_string = generate_version_string(directory, "fix-942360", None)

            assert version_string == "OWASP_CRS/3.4.0-dev", f"Expected OWASP_CRS/3.4.0-dev but got {version_string}"
