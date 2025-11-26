"""Tests for the Logger class."""

import pytest
import logging
from unittest.mock import Mock, patch, call
from crs_linter.logger import Logger, Output


class TestLoggerInit:
    """Tests for Logger initialization."""

    def test_init_native_output_default(self):
        """Test initialization with native output (default)."""
        logger = Logger(output=Output.NATIVE)

        assert logger.output == Output.NATIVE
        assert logger.debugging is False
        assert isinstance(logger.logger, logging.Logger)

    def test_init_native_output_with_debug(self):
        """Test initialization with native output and debug enabled."""
        logger = Logger(output=Output.NATIVE, debug=True)

        assert logger.output == Output.NATIVE
        assert logger.debugging is True
        assert logger.logger.level == logging.DEBUG

    def test_init_github_output(self):
        """Test initialization with GitHub output."""
        logger = Logger(output=Output.GITHUB)

        assert logger.output == Output.GITHUB
        # For GitHub output, logger should be github_action_utils module
        assert logger.logger is not None


class TestLoggerNativeOutput:
    """Tests for Logger with native output."""

    def test_debug_with_debugging_enabled(self):
        """Test debug logging when debugging is enabled."""
        logger = Logger(output=Output.NATIVE, debug=True)

        with patch.object(logger.logger, 'debug') as mock_debug:
            logger.debug("Debug message")
            mock_debug.assert_called_once_with("Debug message")

    def test_debug_with_debugging_disabled(self):
        """Test debug logging when debugging is disabled."""
        logger = Logger(output=Output.NATIVE, debug=False)

        with patch.object(logger.logger, 'debug') as mock_debug:
            logger.debug("Debug message")
            # debug should not be called when debugging is disabled
            mock_debug.assert_not_called()

    def test_error_logging(self):
        """Test error logging."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'error') as mock_error:
            logger.error("Error message")
            mock_error.assert_called_once_with("Error message")

    def test_warning_logging(self):
        """Test warning logging."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'warning') as mock_warning:
            logger.warning("Warning message")
            mock_warning.assert_called_once_with("Warning message")

    def test_info_logging(self):
        """Test info logging."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'info') as mock_info:
            logger.info("Info message")
            mock_info.assert_called_once_with("Info message")

    def test_start_group_does_nothing_for_native(self):
        """Test that start_group does nothing for native output."""
        logger = Logger(output=Output.NATIVE)

        # Should not raise any errors
        logger.start_group("Test group")

    def test_end_group_does_nothing_for_native(self):
        """Test that end_group does nothing for native output."""
        logger = Logger(output=Output.NATIVE)

        # Should not raise any errors
        logger.end_group()


class TestLoggerGitHubOutput:
    """Tests for Logger with GitHub Actions output."""

    def test_debug_with_github_output_and_debugging(self):
        """Test debug logging with GitHub output when debugging is enabled."""
        logger = Logger(output=Output.GITHUB, debug=True)

        with patch.object(logger.logger, 'debug') as mock_debug:
            logger.debug("Debug message", title="Debug")
            mock_debug.assert_called_once_with("Debug message", title="Debug")

    def test_debug_with_github_output_without_debugging(self):
        """Test debug logging with GitHub output when debugging is disabled."""
        logger = Logger(output=Output.GITHUB, debug=False)

        with patch.object(logger.logger, 'debug') as mock_debug:
            logger.debug("Debug message")
            # debug should not be called when debugging is disabled
            mock_debug.assert_not_called()

    def test_error_with_github_output(self):
        """Test error logging with GitHub output."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'error') as mock_error:
            logger.error("Error message", title="Error", file="test.py", line=10)
            mock_error.assert_called_once_with(
                "Error message",
                title="Error",
                file="test.py",
                line=10
            )

    def test_warning_with_github_output(self):
        """Test warning logging with GitHub output."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'warning') as mock_warning:
            logger.warning("Warning message", title="Warning")
            mock_warning.assert_called_once_with("Warning message", title="Warning")

    def test_info_with_github_output(self):
        """Test info logging with GitHub output (maps to notice)."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'notice') as mock_notice:
            logger.info("Info message", title="Info")
            mock_notice.assert_called_once_with("Info message", title="Info")

    def test_start_group_with_github_output(self):
        """Test start_group with GitHub output."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'start_group') as mock_start:
            logger.start_group("Test Group", title="Group Title")
            mock_start.assert_called_once_with("Test Group", title="Group Title")

    def test_end_group_with_github_output(self):
        """Test end_group with GitHub output."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'end_group') as mock_end:
            logger.end_group()
            mock_end.assert_called_once()


class TestLoggerMultipleMessages:
    """Tests for logging multiple messages."""

    def test_multiple_error_messages(self):
        """Test logging multiple error messages."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'error') as mock_error:
            logger.error("Error 1")
            logger.error("Error 2")
            logger.error("Error 3")

            assert mock_error.call_count == 3
            mock_error.assert_has_calls([
                call("Error 1"),
                call("Error 2"),
                call("Error 3")
            ])

    def test_mixed_log_levels(self):
        """Test logging at different levels."""
        logger = Logger(output=Output.NATIVE, debug=True)

        with patch.object(logger.logger, 'debug') as mock_debug, \
             patch.object(logger.logger, 'info') as mock_info, \
             patch.object(logger.logger, 'warning') as mock_warning, \
             patch.object(logger.logger, 'error') as mock_error:

            logger.debug("Debug")
            logger.info("Info")
            logger.warning("Warning")
            logger.error("Error")

            mock_debug.assert_called_once()
            mock_info.assert_called_once()
            mock_warning.assert_called_once()
            mock_error.assert_called_once()


class TestOutputEnum:
    """Tests for the Output enum."""

    def test_output_native_value(self):
        """Test that Output.NATIVE has expected value."""
        assert Output.NATIVE == "native"

    def test_output_github_value(self):
        """Test that Output.GITHUB has expected value."""
        assert Output.GITHUB == "github"

    def test_output_enum_members(self):
        """Test that Output enum has expected members."""
        members = list(Output)
        assert len(members) == 2
        assert Output.NATIVE in members
        assert Output.GITHUB in members


class TestLoggerEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_empty_message(self):
        """Test logging empty message."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'info') as mock_info:
            logger.info("")
            mock_info.assert_called_once_with("")

    def test_long_message(self):
        """Test logging very long message."""
        logger = Logger(output=Output.NATIVE)
        long_message = "x" * 10000

        with patch.object(logger.logger, 'info') as mock_info:
            logger.info(long_message)
            mock_info.assert_called_once_with(long_message)

    def test_message_with_newlines(self):
        """Test logging message with newlines."""
        logger = Logger(output=Output.NATIVE)
        message = "Line 1\nLine 2\nLine 3"

        with patch.object(logger.logger, 'error') as mock_error:
            logger.error(message)
            mock_error.assert_called_once_with(message)

    def test_message_with_special_characters(self):
        """Test logging message with special characters."""
        logger = Logger(output=Output.NATIVE)
        message = "Error: 'test' & \"value\" <tag> %s"

        with patch.object(logger.logger, 'warning') as mock_warning:
            logger.warning(message)
            mock_warning.assert_called_once_with(message)

    def test_unicode_message(self):
        """Test logging message with unicode characters."""
        logger = Logger(output=Output.NATIVE)
        message = "Unicode: 你好 мир 🚀"

        with patch.object(logger.logger, 'info') as mock_info:
            logger.info(message)
            mock_info.assert_called_once_with(message)


class TestLoggerKwargsHandling:
    """Tests for handling keyword arguments."""

    def test_github_error_with_multiple_kwargs(self):
        """Test GitHub error with multiple keyword arguments."""
        logger = Logger(output=Output.GITHUB)

        with patch.object(logger.logger, 'error') as mock_error:
            logger.error(
                "Error",
                title="Title",
                file="test.py",
                line=10,
                col=5,
                end_line=15
            )
            mock_error.assert_called_once_with(
                "Error",
                title="Title",
                file="test.py",
                line=10,
                col=5,
                end_line=15
            )

    def test_native_info_with_kwargs(self):
        """Test native info with keyword arguments."""
        logger = Logger(output=Output.NATIVE)

        with patch.object(logger.logger, 'info') as mock_info:
            logger.info("Info", extra={"key": "value"})
            mock_info.assert_called_once_with("Info", extra={"key": "value"})
