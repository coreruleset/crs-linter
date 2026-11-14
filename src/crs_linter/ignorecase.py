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
# (?i), (?i-s:...), (?^i): a leading ^ resets the flags before applying the new ones
_GROUP_FLAGS = re.compile(r"\(\?(\^?)([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])")
_UNSUPPORTED_GROUP = re.compile(r"\(\?[+-]?\d")
# non-capturing and look-around prefixes that open a group without flags
_PLAIN_GROUP_PREFIXES = ("(?:", "(?=", "(?!", "(?<=", "(?<!", "(?>", "(?|")
_NAMED_GROUP = re.compile(r"\(\?(?:P?<[A-Za-z_]\w*>|'[A-Za-z_]\w*')")
# \k<name>, \g{1}, \1: backreferences match case-insensitively under (?i)
_BACKREF = re.compile(r"\\(?:k<\w+>|k\{\w+\}|k'\w+'|g\{-?\w+\}|g-?\d+|\d+)")
# \p{Lu}, \pL: property classes are case dependent
_PROPERTY = re.compile(r"\\[pP](?:\{\^?\w+\}|\w)")
# \x41, \x{41}, \012: the character they stand for decides whether they are a letter
_HEX_ESCAPE = re.compile(r"\\x(?:\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{0,2}))")
_OCTAL_ESCAPE = re.compile(r"\\0([0-7]{0,2})")
_POSIX_CLASS = re.compile(r"\[:\^?\w+:\]")
_LETTER = re.compile(r"[A-Za-z]|[^\x00-\x7f]")


def _escape(pattern: str, i: int) -> Tuple[int, bool]:
    """Return (end, is_letter) for the escape sequence that starts at `i`.

    Only ASCII letters count for numeric escapes: whether a byte above 0x7f
    has a case depends on the locale and on the UTF mode, which a linter
    cannot know.
    """
    m = _PROPERTY.match(pattern, i)
    if m:
        return m.end(), True
    m = _HEX_ESCAPE.match(pattern, i)
    if m:
        value = int(m.group(1) or m.group(2) or "0", 16)
        return m.end(), value < 0x80 and chr(value).isalpha()
    m = _OCTAL_ESCAPE.match(pattern, i)
    if m:
        value = int(m.group(1) or "0", 8)
        return m.end(), value < 0x80 and chr(value).isalpha()
    if pattern.startswith("\\c", i):
        return i + 3, False
    return i + 2, False


def _class_has_letter(body: str) -> bool:
    """True when the character class body has a letter, a property or a posix class."""
    i, n = 0, len(body)
    while i < n:
        if body[i] == "\\" and i + 1 < n:
            i, is_letter = _escape(body, i)
        elif body[i] == "[" and _POSIX_CLASS.match(body, i):
            return True
        else:
            is_letter = bool(_LETTER.match(body[i]))
            i += 1
        if is_letter:
            return True
    return False


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
        elif c == "[" and _POSIX_CLASS.match(pattern, i):
            i = _POSIX_CLASS.match(pattern, i).end()
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
            m = _BACKREF.match(pattern, i)
            if m and not _OCTAL_ESCAPE.match(pattern, i):
                letter()
                i = m.end()
                continue
            # \d, \w and \b do not depend on case folding, \x61 and \p{Lu} do
            i, is_letter = _escape(pattern, i)
            if is_letter:
                letter()
            continue

        if c == "[":
            end = _class_end(pattern, i)
            if end == -1:
                return Coverage.UNKNOWN
            body = pattern[i + 1:end - 1]
            if _class_has_letter(body):
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
            if pattern.startswith(("(*", "(?R", "(?&", "(?P>", "(?P=", "(?("), i) or _UNSUPPORTED_GROUP.match(pattern, i):
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
            reset, on, off, end = m.group(1), m.group(2), m.group(3) or "", m.group(4)
            if end == ":":
                stack.append((ignorecase, extended))
            if reset:
                ignorecase = extended = False
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


# Transformations that are harmless after t:lowercase: they only remove or
# normalise characters, so (?i) on the pattern gives the same match. Anything
# else (decoders that bring upper case back, hexEncode, md5, uppercase...) makes
# (?i) a different rule.
_SAFE_AFTER_LOWERCASE = frozenset((
    "lowercase", "cmdline", "compresswhitespace", "length", "normalisepath",
    "normalisepathwin", "normalizepath", "normalizepathwin", "removecomments",
    "removecommentschar", "removenulls", "removewhitespace", "replacecomments",
    "replacenulls", "trim", "trimleft", "trimright",
))

# %{tx.0}, %{tx.1} and %{matched_var}, %{matched_vars}; not %{matched_var_name}
_TX_REF = re.compile(r"%\{tx\.\d+\}", re.IGNORECASE)
_MATCHED_REF = re.compile(r"%\{matched_vars?\}", re.IGNORECASE)
_LOG_ACTIONS = frozenset(("logdata", "msg", "tag"))


def _reads(link, tx: bool, matched: bool) -> bool:
    """True when the link reads TX:N (if `tx`) or MATCHED_VAR(S) (if `matched`).

    Reads in logdata and msg do not count: they only change what is logged.
    """
    for v in link.get("variables", ()):
        name = v.get("variable", "").upper()
        if matched and name in ("MATCHED_VAR", "MATCHED_VARS"):
            return True
        if tx and name == "TX" and str(v.get("variable_part", "")).isdigit():
            return True
    texts = [link.get("operator_argument") or ""]
    texts += [
        str(a.get("act_arg") or "") + str(a.get("act_arg_val") or "")
        for a in link.get("actions", ())
        if a["act_name"] not in _LOG_ACTIONS
    ]
    return any((tx and _TX_REF.search(t)) or (matched and _MATCHED_REF.search(t)) for t in texts)


def _reads_value(chain, n: int) -> bool:
    """True when something reads the value that link `n` of `chain` lowercased.

    - the link's own actions (setvar:...=%{tx.0}, %{matched_var}), where
      %{tx.N} only holds something if the link captures
    - MATCHED_VAR(S) in the next link, which holds this link's match; later
      links see the match of the link before them
    - TX:N in any later link, until another link captures and overwrites it
    """
    link = chain[n]
    captures = any(a["act_name"] == "capture" for a in link["actions"])
    if _reads({"actions": link["actions"]}, tx=captures, matched=True):
        return True
    for k in range(n + 1, len(chain)):
        if _reads(chain[k], tx=captures, matched=(k == n + 1)):
            return True
        if any(a["act_name"] == "capture" for a in chain[k]["actions"]):
            captures = False
    return False


def lowercase_rx_rules(data):
    """Yield (rule id, lowercase actions, coverage, reads value, alters after) for each
    @rx link with an effective t:lowercase. An empty operator is an implicit @rx.

    "reads value" means a later link or action reads the lowercased value
    (MATCHED_VAR, %{tx.0}...), so t:lowercase does more than make the match
    case-insensitive. "alters after" means a transformation after t:lowercase
    changes the value beyond removing characters, so (?i) is not equivalent.
    Only the transformations after the last t:none count, because t:none
    cancels the ones before it.
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
            transforms = [a for a in d["actions"] if a["act_name"] == "t"]
            for k, a in enumerate(transforms):
                if a["act_arg"].lower() == "none":
                    transforms = transforms[k + 1:]
            lowered = [a for a in transforms if a["act_arg"].lower() == "lowercase"]
            if not lowered:
                continue
            after = [a["act_arg"].lower() for a in transforms[transforms.index(lowered[-1]) + 1:]]
            alters = any(t not in _SAFE_AFTER_LOWERCASE for t in after)
            yield ruleid, lowered, ignorecase_coverage(d["operator_argument"]), _reads_value(chain, n), alters
