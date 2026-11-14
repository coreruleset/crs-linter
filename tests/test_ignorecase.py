"""Tests for the ignorecase coverage helper."""

import pytest

from crs_linter.ignorecase import Coverage, ignorecase_coverage


@pytest.mark.parametrize("pattern,expected", [
    ("(?i)foo", Coverage.FULL),
    ("^(?i)foo", Coverage.FULL),
    ("(?i:foo)", Coverage.FULL),
    ("(?si)foo", Coverage.FULL),
    ("(?i-s:foo)", Coverage.FULL),
    ("(?i:foo)|(?si)bar", Coverage.FULL),
    ("(?i)[a-z]+\\1", Coverage.FULL),
    ("(?i)\\Qa.b\\E", Coverage.FULL),
    ("(?#note)(?i)x", Coverage.FULL),
    ("(?i:foo)|bar", Coverage.PARTIAL),
    ("foo(?i)bar", Coverage.PARTIAL),
    ("(?i)foo(?-i)bar", Coverage.PARTIAL),
    ("(?i)(foo|bar)(?-i:baz)", Coverage.PARTIAL),
    ("((?i)a)b", Coverage.PARTIAL),
    ("[a-z](?i)x", Coverage.PARTIAL),
    ("(?<n>a)(?i)b", Coverage.PARTIAL),
    ("foo", Coverage.NONE),
    ("^\\x61(?i)b$", Coverage.PARTIAL),  # \x61 is "a": it is not covered by a later (?i)
    ("(?i)\\x61b", Coverage.FULL),
    ("\\x41", Coverage.NONE),
    ("\\x{41}", Coverage.NONE),
    ("\\x5c(?i)foo", Coverage.FULL),  # \x5c is a backslash, its "c" is not an uncovered letter
    ("\\x5c(?i)", Coverage.NOLETTERS),  # \x5c is a backslash, its "c" is not a letter
    ("\\xc0\\x80", Coverage.NOLETTERS),
    ("\\0101", Coverage.NOLETTERS),
    ("[\\x41]", Coverage.NONE),
    ("(?i)a(?^)b", Coverage.PARTIAL),  # (?^) turns the flags off again
    ("(?i)a(?^i)b", Coverage.FULL),
    ("(?i)[[:,]x(?-i)BAR:]]", Coverage.PARTIAL),  # [: here does not start a posix class
    ("(?i)[[:alpha:]]", Coverage.FULL),
    ("(?-i)foo", Coverage.NONE),
    ("foo\\\\(?i)", Coverage.NONE),  # an escaped backslash, then a real flag with nothing after it
    ("(?x)foo # (?i) note", Coverage.NONE),  # the flag is inside an extended-mode comment
    ("a{x}", Coverage.NONE),
    ("[^\\x00-\\x7f]", Coverage.NOLETTERS),  # hex digits in a class are not letters
    ("[\\x{bc}\\101\\]]", Coverage.NOLETTERS),
    ("[^a-f]", Coverage.NONE),
    ("^[0-9]+$", Coverage.NOLETTERS),
    ("\\d+\\.\\w", Coverage.NOLETTERS),
    ("(foo", Coverage.UNKNOWN),
    ("foo)", Coverage.UNKNOWN),
    ("[abc", Coverage.UNKNOWN),
    ("(?R)", Coverage.UNKNOWN),
    ("(?(1)a|b)", Coverage.UNKNOWN),
    ("foo\\", Coverage.UNKNOWN),
])
def test_ignorecase_coverage(pattern, expected):
    assert ignorecase_coverage(pattern) is expected
