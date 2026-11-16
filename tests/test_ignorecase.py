"""Tests for the ignorecase coverage helper."""

import pytest

from crs_linter.ignorecase import Coverage, dead_uppercase, ignorecase_coverage


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
    ("(?i)[[:alpha:]]", Coverage.NOLETTERS),  # holds both cases of every letter
    ("[[:upper:]](?i)a", Coverage.PARTIAL),
    ("[A-Za-z](?i)foo", Coverage.FULL),  # matches the same with or without (?i)
    ("^[\\Q\\a\\E](?i)b$", Coverage.PARTIAL),  # \Q...\E in a class quotes "\" and "a"
    ("^[\\Q]\\E](?i)b$", Coverage.FULL),  # a quoted ] does not end the class
    ("^[\\x40-\\x60](?i)a$", Coverage.PARTIAL),  # the range holds A-Z
    ("[!-~](?i)a", Coverage.FULL),  # the range holds both cases of every letter
    ("[0-\\x5a](?i)a", Coverage.PARTIAL),
    ("(?-i)foo", Coverage.NONE),
    ("foo\\\\(?i)", Coverage.NONE),  # an escaped backslash, then a real flag with nothing after it
    ("(?x)foo # (?i) note", Coverage.NONE),  # the flag is inside an extended-mode comment
    ("a{x}", Coverage.NONE),
    ("[^\\x00-\\x7f]", Coverage.NOLETTERS),  # hex digits in a class are not letters
    ("[\\x{bc}\\101\\]]", Coverage.NONE),  # in a class \101 is always octal, "A"
    ("[\\x{bc}\\060\\]]", Coverage.NOLETTERS),
    ("\\60(?i)abc", Coverage.FULL),  # no group 60, so \60 is octal "0", not a backreference
    ("\\101", Coverage.NONE),  # octal "A"
    ("(a)\\1", Coverage.NONE),
    ("(?i)(a)\\1", Coverage.FULL),
    ("\\8(?i)a", Coverage.PARTIAL),  # \8 is always a backreference
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


@pytest.mark.parametrize("pattern,expected", [
    ("FOO", True),
    ("^[A-Z]+$", True),
    ("[^A-Z]", True),
    ("\\x41", True),
    ("\\101", True),
    ("\\QABC\\E", True),
    ("(?i)FOO", False),
    ("(?i:A)b", False),
    ("foo", False),
    ("[0-9A-Z_a-z]+", False),
    ("[A-z]", False),
    ("\\p{Lu}", False),
    ("(a)\\1", False),
    ("^[Ab]$", True),  # (?i) would let "a" in
    ("^[^A]+$", True),  # (?i) would keep "a" out
    ("[\\x40-\\x60]", True),
    ("[[:upper:]]", True),
    ("[[:alpha:]]", False),
    ("[Aa]", False),
])
def test_dead_uppercase(pattern, expected):
    assert dead_uppercase(pattern) is expected
