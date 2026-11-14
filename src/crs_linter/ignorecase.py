"""Tell how much of a PCRE pattern the case-insensitive flag covers.

Python's `re` cannot be used for this: it rejects a mid-pattern `(?i)` and does
not know `\\Q...\\E`. This is a small tokenizer that only tracks what the checks
need: for every atom that has a letter in it, is the `i` flag on at that point?
"""

import enum
import re
from typing import List, Optional, Set, Tuple


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
# \k<name>, \g{1}: backreferences match case-insensitively under (?i)
_BACKREF = re.compile(r"\\(?:k<\w+>|k\{\w+\}|k'\w+'|g\{-?\w+\}|g-?\d+)")
# \1, \60: a backreference or an octal escape, depending on the number
_NUMBERED = re.compile(r"\\([1-9]\d*)")
_OCTAL_DIGITS = re.compile(r"[0-7]{1,3}")
# \p{Lu}, \pL: property classes are case dependent
_PROPERTY = re.compile(r"\\[pP](?:\{\^?\w+\}|\w)")
# \x41, \x{41}, \012: the character they stand for decides whether they are a letter
_HEX_ESCAPE = re.compile(r"\\x(?:\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{0,2}))")
_OCTAL_ESCAPE = re.compile(r"\\0([0-7]{0,2})")
# inside a character class \101 is always octal
_CLASS_OCTAL_ESCAPE = re.compile(r"\\([1-7][0-7]{0,2})")
_POSIX_CLASS = re.compile(r"\[:\^?\w+:\]")
_LETTER = re.compile(r"[A-Za-z]|[^\x00-\x7f]")

# what a single character is, as far as case folding goes
LOWER, UPPER, OTHER_LETTER = "lower", "upper", "letter"


def _kind(ch: str) -> Optional[str]:
    """Return UPPER or LOWER for an ASCII letter, OTHER_LETTER for anything
    else case folding may affect, and None for the rest."""
    if "A" <= ch <= "Z":
        return UPPER
    if "a" <= ch <= "z":
        return LOWER
    return OTHER_LETTER if _LETTER.match(ch) else None


def _code_kind(value: int) -> Optional[str]:
    """Kind of the character a numeric escape stands for.

    Only ASCII letters count: whether a byte above 0x7f has a case depends on
    the locale and on the UTF mode, which a linter cannot know.
    """
    return _kind(chr(value)) if value < 0x80 and chr(value).isalpha() else None


def _escape(pattern: str, i: int, in_class: bool = False) -> Tuple[int, Optional[str]]:
    """Return (end, kind) for the escape sequence that starts at `i`."""
    m = _PROPERTY.match(pattern, i)
    if m:
        return m.end(), OTHER_LETTER
    m = _HEX_ESCAPE.match(pattern, i)
    if m:
        return m.end(), _code_kind(int(m.group(1) or m.group(2) or "0", 16))
    m = _OCTAL_ESCAPE.match(pattern, i)
    if m:
        return m.end(), _code_kind(int(m.group(1) or "0", 8))
    m = _CLASS_OCTAL_ESCAPE.match(pattern, i) if in_class else None
    if m:
        return m.end(), _code_kind(int(m.group(1), 8))
    if pattern.startswith("\\c", i):
        return i + 3, None
    return i + 2, None


def _class_kinds(body: str) -> Set[str]:
    """Kinds of the letters in a character class body. A property or a posix
    class counts as OTHER_LETTER."""
    kinds: Set[str] = set()
    i, n = 0, len(body)
    while i < n:
        if body[i] == "\\" and i + 1 < n:
            i, kind = _escape(body, i, in_class=True)
        elif body[i] == "[" and _POSIX_CLASS.match(body, i):
            i, kind = _POSIX_CLASS.match(body, i).end(), OTHER_LETTER
        else:
            kind = _kind(body[i])
            i += 1
        if kind:
            kinds.add(kind)
    return kinds


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
    return _scan(pattern)[0]


def dead_uppercase(pattern: str) -> bool:
    """True when the pattern has an upper-case letter outside (?i) that cannot
    match lowercased input, such as `FOO` or `[A-Z]`. Adding (?i) to such a
    pattern makes it match more, so it is not a plain replacement for
    t:lowercase. A class with both cases, such as `[A-Za-z]`, does not count."""
    return _scan(pattern)[1]


def _scan(pattern: str) -> Tuple[Coverage, bool]:
    """Return the coverage of `pattern` and whether it has a dead upper-case letter."""
    covered = uncovered = groups = 0
    upper = False
    ignorecase = extended = False
    stack: List[Tuple[bool, bool]] = []
    i, n = 0, len(pattern)

    def letter(kinds=(OTHER_LETTER,)):
        nonlocal covered, uncovered, upper
        if ignorecase:
            covered += 1
        else:
            uncovered += 1
            if UPPER in kinds and LOWER not in kinds:
                upper = True

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
                return Coverage.UNKNOWN, False
            if pattern.startswith("\\Q", i):
                end = pattern.find("\\E", i + 2)
                body = pattern[i + 2:] if end == -1 else pattern[i + 2:end]
                for ch in body:
                    if ch.isalpha():
                        letter((_kind(ch),))
                i = n if end == -1 else end + 2
                continue
            m = _BACKREF.match(pattern, i)
            if m:
                letter()
                i = m.end()
                continue
            m = _NUMBERED.match(pattern, i)
            if m:
                # PCRE: a backreference if below 10, starting with 8 or 9, or
                # not above the number of groups so far; octal otherwise
                digits = m.group(1)
                if int(digits) < 10 or digits[0] in "89" or int(digits) <= groups:
                    letter()
                    i = m.end()
                else:
                    octal = _OCTAL_DIGITS.match(digits).group()
                    kind = _code_kind(int(octal, 8))
                    if kind:
                        letter((kind,))
                    i += 1 + len(octal)
                continue
            # \d, \w and \b do not depend on case folding, \x61 and \p{Lu} do
            i, kind = _escape(pattern, i)
            if kind:
                letter((kind,))
            continue

        if c == "[":
            end = _class_end(pattern, i)
            if end == -1:
                return Coverage.UNKNOWN, False
            body = pattern[i + 1:end - 1]
            kinds = _class_kinds(body)
            if kinds:
                letter(kinds)
            i = end
            continue

        if c == "(":
            if pattern.startswith("(?#", i):
                end = pattern.find(")", i)
                if end == -1:
                    return Coverage.UNKNOWN, False
                i = end + 1
                continue
            if pattern.startswith(("(*", "(?R", "(?&", "(?P>", "(?P=", "(?("), i) or _UNSUPPORTED_GROUP.match(pattern, i):
                return Coverage.UNKNOWN, False
            plain = next((p for p in _PLAIN_GROUP_PREFIXES if pattern.startswith(p, i)), None)
            named = _NAMED_GROUP.match(pattern, i)
            if plain or named or not pattern.startswith("(?", i):
                if not plain:
                    groups += 1
                stack.append((ignorecase, extended))
                i += len(plain) if plain else named.end() - i if named else 1
                continue
            m = _GROUP_FLAGS.match(pattern, i)
            if not m:
                return Coverage.UNKNOWN, False
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
                return Coverage.UNKNOWN, False
            ignorecase, extended = stack.pop()
            i += 1
            continue

        if c == "{":
            m = _QUANTIFIER.match(pattern, i)
            i = m.end() if m else i + 1
            continue

        if c.isalpha():
            letter((_kind(c),))
        i += 1

    if stack:
        return Coverage.UNKNOWN, False
    if not covered and not uncovered:
        return Coverage.NOLETTERS, False
    if not uncovered:
        return Coverage.FULL, False
    return (Coverage.NONE if not covered else Coverage.PARTIAL), upper


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
    """Yield (rule id, lowercase actions, coverage, reads value, alters after,
    dead upper case) for each
    @rx link with an effective t:lowercase. An empty operator is an implicit @rx.

    "reads value" means a later link or action reads the lowercased value
    (MATCHED_VAR, %{tx.0}...), so t:lowercase does more than make the match
    case-insensitive. "alters after" means a transformation after t:lowercase
    changes the value beyond removing characters, so (?i) is not equivalent.
    Only the transformations after the last t:none count, because t:none
    cancels the ones before it. "dead upper case" is what dead_uppercase() says
    about the pattern.
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
            names = [a["act_arg"].lower() for a in transforms]
            last_none = max((k for k, t in enumerate(names) if t == "none"), default=-1)
            transforms, names = transforms[last_none + 1:], names[last_none + 1:]
            positions = [k for k, t in enumerate(names) if t == "lowercase"]
            if not positions:
                continue
            lowered = [transforms[k] for k in positions]
            after = names[positions[-1] + 1:]
            alters = any(t not in _SAFE_AFTER_LOWERCASE for t in after)
            coverage, upper = _scan(d["operator_argument"])
            yield ruleid, lowered, coverage, _reads_value(chain, n), alters, upper
