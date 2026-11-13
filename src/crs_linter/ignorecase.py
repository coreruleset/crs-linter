"""Tell how much of a PCRE pattern the case-insensitive flag covers.

Python's `re` cannot be used for this: it rejects a mid-pattern `(?i)` and does
not know `\\Q...\\E`. This is a small tokenizer that only tracks what the checks
need: for every atom that has a letter in it, is the `i` flag on at that point?
"""

import enum
import re
from typing import List, Tuple


class Coverage(enum.Enum):
    FULL = "full"  # every letter in the pattern is matched case-insensitively
    PARTIAL = "partial"  # some letters are, some are not
    NONE = "none"  # no letter is
    NOLETTERS = "noletters"  # the pattern has nothing that case folding affects
    UNKNOWN = "unknown"  # recursion, conditionals, verbs, or a malformed pattern


_QUANTIFIER = re.compile(r"\{\d*(?:,\d*)?\}")
_GROUP_FLAGS = re.compile(r"\(\?\^?([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])")
# non-capturing and look-around prefixes that open a group without flags
_PLAIN_GROUP_PREFIXES = ("(?:", "(?=", "(?!", "(?<=", "(?<!", "(?>", "(?|")
_NAMED_GROUP = re.compile(r"\(\?(?:P?<[A-Za-z_]\w*>|'[A-Za-z_]\w*')")
# \k<name>, \g{1}, \1: backreferences match case-insensitively under (?i)
_BACKREF = re.compile(r"\\(?:k<\w+>|k\{\w+\}|k'\w+'|g\{-?\w+\}|g-?\d+|\d+)")
# \p{Lu}, \pL: property classes are case dependent
_PROPERTY = re.compile(r"\\[pP](?:\{\^?\w+\}|\w)")
# escapes inside a character class that are not letters: \x7f, \x{bc}, \101, \n, \]
_CLASS_ESCAPE = re.compile(r"\\(?:x\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{0,2}|[0-7]{1,3}|c.|.)", re.DOTALL)
_CLASS_LETTER = re.compile(r"[A-Za-z]|[^\x00-\x7f]")


def _class_end(pattern: str, i: int) -> int:
    """Return the index after the character class that starts at `i`, or -1."""
    n = len(pattern)
    i += 1
    if i < n and pattern[i] == "^":
        i += 1
    if i < n and pattern[i] == "]":  # a leading ] is a literal
        i += 1
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
        elif c == "[" and pattern.startswith("[:", i) and ":]" in pattern[i:]:
            i = pattern.index(":]", i) + 2
        elif c == "]":
            return i + 1
        else:
            i += 1
    return -1


def ignorecase_coverage(pattern: str) -> Coverage:
    """Classify `pattern` by how many of its letters the `(?i)` flag covers."""
    covered = uncovered = 0
    ignorecase = extended = False
    stack: List[Tuple[bool, bool]] = []
    i, n = 0, len(pattern)

    def letter():
        nonlocal covered, uncovered
        if ignorecase:
            covered += 1
        else:
            uncovered += 1

    while i < n:
        c = pattern[i]

        if extended:
            if c.isspace():
                i += 1
                continue
            if c == "#":
                while i < n and pattern[i] != "\n":
                    i += 1
                continue

        if c == "\\":
            if i + 1 >= n:
                return Coverage.UNKNOWN
            if pattern.startswith("\\Q", i):
                end = pattern.find("\\E", i + 2)
                body = pattern[i + 2:] if end == -1 else pattern[i + 2:end]
                for ch in body:
                    if ch.isalpha():
                        letter()
                i = n if end == -1 else end + 2
                continue
            m = _BACKREF.match(pattern, i) or _PROPERTY.match(pattern, i)
            if m:
                letter()
                i = m.end()
                continue
            # an escaped letter is a class (\d, \w), an anchor (\b) or a
            # control character (\n): none of them depends on case folding
            i += 2
            continue

        if c == "[":
            end = _class_end(pattern, i)
            if end == -1:
                return Coverage.UNKNOWN
            body = pattern[i + 1:end - 1]
            if _PROPERTY.search(body) or re.search(r"\[:\w+:\]", body) or _CLASS_LETTER.search(_CLASS_ESCAPE.sub("", body)):
                letter()
            i = end
            continue

        if c == "(":
            if pattern.startswith("(?#", i):
                end = pattern.find(")", i)
                if end == -1:
                    return Coverage.UNKNOWN
                i = end + 1
                continue
            if pattern.startswith(("(*", "(?R", "(?&", "(?P>", "(?P=", "(?("), i) or re.match(r"\(\?[+-]?\d", pattern[i:]):
                return Coverage.UNKNOWN
            plain = next((p for p in _PLAIN_GROUP_PREFIXES if pattern.startswith(p, i)), None)
            named = _NAMED_GROUP.match(pattern, i)
            if plain or named or not pattern.startswith("(?", i):
                stack.append((ignorecase, extended))
                i += len(plain) if plain else named.end() - i if named else 1
                continue
            m = _GROUP_FLAGS.match(pattern, i)
            if not m:
                return Coverage.UNKNOWN
            on, off, end = m.group(1), m.group(2) or "", m.group(3)
            if end == ":":
                stack.append((ignorecase, extended))
            ignorecase = (ignorecase or "i" in on) and "i" not in off
            extended = (extended or "x" in on) and "x" not in off
            i = m.end()
            continue

        if c == ")":
            if not stack:
                return Coverage.UNKNOWN
            ignorecase, extended = stack.pop()
            i += 1
            continue

        if c == "{":
            m = _QUANTIFIER.match(pattern, i)
            i = m.end() if m else i + 1
            continue

        if c.isalpha():
            letter()
        i += 1

    if stack:
        return Coverage.UNKNOWN
    if not covered and not uncovered:
        return Coverage.NOLETTERS
    if not uncovered:
        return Coverage.FULL
    return Coverage.NONE if not covered else Coverage.PARTIAL


# transformations that can bring upper case back after t:lowercase
_DECODERS = frozenset((
    "urldecode", "urldecodeuni", "htmlentitydecode", "base64decode",
    "base64decodeext", "hexdecode", "jsdecode", "cssdecode", "utf8tounicode",
))


# a later reference to the matched or captured value: %{tx.0}, %{tx.1}, %{matched_var}
_VALUE_REF = re.compile(r"%\{(?:tx\.\d|matched_var)", re.IGNORECASE)
_LOG_ACTIONS = frozenset(("logdata", "msg", "tag"))


def _reads_value(links) -> bool:
    """True when a rule link reads the matched or captured value of an earlier one."""
    for link in links:
        for v in link.get("variables", ()):
            name = v.get("variable", "").upper()
            if name.startswith("MATCHED_VAR") or (name == "TX" and str(v.get("variable_part", "")).isdigit()):
                return True
        for a in link.get("actions", ()):
            if a["act_name"] not in _LOG_ACTIONS and _VALUE_REF.search(str(a.get("act_arg") or "") + str(a.get("act_arg_val") or "")):
                return True
    return False


def lowercase_rx_rules(data):
    """Yield (rule id, lowercase actions, coverage, reads value, decodes after) for each
    @rx link with t:lowercase. An empty operator is an implicit @rx.

    "reads value" means a later link or action reads the lowercased value
    (MATCHED_VAR, %{tx.0}...), so t:lowercase does more than make the match
    case-insensitive. Logging only (logdata, msg) does not count.
    """
    links = []
    chain = []
    chained = False
    for d in data:
        if d["type"].lower() != "secrule" or "actions" not in d:
            continue
        if not chained:
            chain = []
            links.append(chain)
        chain.append(d)
        chained = any(a["act_name"] == "chain" for a in d["actions"])

    for chain in links:
        ruleid = next((int(a["act_arg"]) for d in chain for a in d["actions"] if a["act_name"] == "id"), 0)
        for n, d in enumerate(chain):
            if d["operator"].lower() not in ("", "@rx"):
                continue
            actions = d["actions"]
            lowered = [a for a in actions if a["act_name"] == "t" and a["act_arg"].lower() == "lowercase"]
            if not lowered:
                continue
            names = [a["act_arg"].lower() for a in actions if a["act_name"] == "t"]
            decodes = any(t in _DECODERS for t in names[names.index("lowercase") + 1:])
            # the link's own actions and every later link
            reads = _reads_value([{"actions": actions}] + chain[n + 1:])
            yield ruleid, lowered, ignorecase_coverage(d["operator_argument"]), reads, decodes
