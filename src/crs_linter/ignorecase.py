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
_PROPERTY = re.compile(r"\\[pP](?:\{\^?([\w&]+)\}|(\w))")
# \p{Lu}, \p{Ll}, \p{Lt}: PCRE2 before 10.45 matches them case-sensitively even
# under (?i), so (?i)\p{Ll} does not match "A" there
_CASE_PROPERTIES = frozenset(("lu", "ll", "lt", "lc", "l&"))
# \x41, \x{41}, \012: the character they stand for decides whether they are a letter
_HEX_ESCAPE = re.compile(r"\\x(?:\{([0-9a-fA-F]+)\}|([0-9a-fA-F]{0,2}))")
_OCTAL_ESCAPE = re.compile(r"\\0([0-7]{0,2})")
# inside a character class \101 is always octal
_CLASS_OCTAL_ESCAPE = re.compile(r"\\([1-7][0-7]{0,2})")
_POSIX_CLASS = re.compile(r"\[:(\^?)(\w+):\]")
# \n, \t... and, inside a class, \b (backspace)
_SIMPLE_ESCAPES = {"a": 7, "e": 27, "f": 12, "n": 10, "r": 13, "t": 9}

_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
_POSIX_LETTERS = {
    "upper": (_UPPER, frozenset()),
    "lower": (frozenset(), _LOWER),
    "alpha": (_UPPER, _LOWER),
    "alnum": (_UPPER, _LOWER),
    "word": (_UPPER, _LOWER),
    "xdigit": (frozenset("ABCDEF"), frozenset("abcdef")),
}


def _escape(pattern: str, i: int, in_class: bool = False) -> Tuple[int, Optional[int], Optional[str]]:
    """Return (end, code point, property) for the escape sequence at `i`.

    The property is None for anything but \p and \P, "case" for a property
    that names a case (\p{Lu}, \P{Ll}...) and "other" for the rest.

    The code point is None for escapes that do not stand for one character,
    such as \\d or \\w, whose meaning does not depend on case folding.
    """
    m = _PROPERTY.match(pattern, i)
    if m:
        name = (m.group(1) or m.group(2)).lower().replace("_", "").replace(" ", "")
        return m.end(), None, "case" if name in _CASE_PROPERTIES else "other"
    m = _HEX_ESCAPE.match(pattern, i)
    if m:
        return m.end(), int(m.group(1) or m.group(2) or "0", 16), None
    m = _OCTAL_ESCAPE.match(pattern, i)
    if m:
        return m.end(), int(m.group(1) or "0", 8), None
    m = _CLASS_OCTAL_ESCAPE.match(pattern, i) if in_class else None
    if m:
        return m.end(), int(m.group(1), 8), None
    if pattern.startswith("\\c", i):
        return i + 3, None, None
    ch = pattern[i + 1]
    if ch in _SIMPLE_ESCAPES:
        return i + 2, _SIMPLE_ESCAPES[ch], None
    if in_class and ch == "b":
        return i + 2, 8, None
    return i + 2, (None if ch.isalnum() else ord(ch)), None


def _ascii_letter(value: Optional[int]) -> Optional[str]:
    """The ASCII letter a numeric escape stands for, or None.

    Only ASCII letters count: whether a byte above 0x7f has a case depends on
    the locale and on the UTF mode, which a linter cannot know.
    """
    if value is not None and value < 0x80 and chr(value).isalpha():
        return chr(value)
    return None


def _class_letters(body: str) -> Tuple[Set[str], Set[str], bool, bool]:
    """Return (upper-case letters, lower-case letters, other letters, case
    property) of a character class body, without its leading ^.

    Ranges are expanded, so `[\\x40-\\x60]` holds A-Z. "other letters" is set
    for non-ASCII characters, properties and posix classes whose case
    behaviour is not modelled.
    """
    upper: Set[str] = set()
    lower: Set[str] = set()
    other = case_property = False
    # each item is a code point, a "-" that may form a range, or None for a set
    items: List[Tuple[Optional[int], bool]] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if body.startswith("\\Q", i):
            end = body.find("\\E", i + 2)
            quoted = body[i + 2:] if end == -1 else body[i + 2:end]
            items.extend((ord(q), False) for q in quoted)
            i = n if end == -1 else end + 2
        elif body.startswith("\\E", i):
            i += 2
        elif c == "\\" and i + 1 < n:
            i, value, prop = _escape(body, i, in_class=True)
            other = other or prop is not None
            case_property = case_property or prop == "case"
            items.append((value, False))
        elif c == "[" and _POSIX_CLASS.match(body, i):
            m = _POSIX_CLASS.match(body, i)
            letters = _POSIX_LETTERS.get(m.group(2).lower())
            if letters and not m.group(1):
                upper |= letters[0]
                lower |= letters[1]
            elif letters:
                other = True
            items.append((None, False))
            i = m.end()
        else:
            if ord(c) > 0x7f:
                other = True
            items.append((ord(c), c == "-"))
            i += 1

    k = 0
    while k < len(items):
        value, _ = items[k]
        if (
            value is not None and k + 2 < len(items)
            and items[k + 1][1] and items[k + 2][0] is not None
        ):
            first, last = value, items[k + 2][0]
            k += 3
        else:
            first = last = value
            k += 1
        if first is None:
            continue
        for cp in range(max(first, 0x41), min(last, 0x7a) + 1):
            if chr(cp) in _UPPER:
                upper.add(chr(cp))
            elif chr(cp) in _LOWER:
                lower.add(chr(cp))
    return upper, lower, other, case_property


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
        if pattern.startswith("\\Q", i):
            end = pattern.find("\\E", i + 2)
            if end == -1:
                return -1
            i = end + 2
        elif c == "\\":
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
    """True when part of the pattern outside (?i) treats the two cases of a
    letter differently: an upper-case letter that lowercased input never has,
    such as `FOO`, `[A-Z]`, `[Ab]` or `[^A]`, or a case property such as
    `\\p{Lu}`. Replacing t:lowercase with (?i) changes which inputs such a
    pattern matches. A class with both cases, such as `[A-Za-z]`, does not
    count."""
    return _scan(pattern)[1]


def _scan(pattern: str) -> Tuple[Coverage, bool]:
    """Return the coverage of `pattern` and whether it has a dead upper-case letter."""
    covered = uncovered = groups = 0
    upper = False
    ignorecase = extended = False
    stack: List[Tuple[bool, bool]] = []
    i, n = 0, len(pattern)

    def letter(dead: bool = False, case_property: bool = False):
        """Count a letter atom; `dead` when, without (?i), it holds an
        upper-case letter whose lower-case form it does not also hold. A case
        property is never covered, since (?i) may not apply to it."""
        nonlocal covered, uncovered, upper
        if ignorecase and not case_property:
            covered += 1
        else:
            uncovered += 1
            upper = upper or dead

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
                        letter(ch in _UPPER)
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
                    ch = _ascii_letter(int(octal, 8))
                    if ch:
                        letter(ch in _UPPER)
                    i += 1 + len(octal)
                continue
            # \d, \w and \b do not depend on case folding, \x61 and \p{Lu} do
            i, value, prop = _escape(pattern, i)
            ch = _ascii_letter(value)
            if prop == "case":
                letter(dead=True, case_property=True)
            elif prop or ch:
                letter(ch is not None and ch in _UPPER)
            continue

        if c == "[":
            end = _class_end(pattern, i)
            if end == -1:
                return Coverage.UNKNOWN, False
            body = pattern[i + 1:end - 1]
            if body.startswith("^"):
                body = body[1:]
            # [Ab] and [^A] are dead in part: t:lowercase input never has "A",
            # but (?i) would also let "a" in, so every upper-case letter needs
            # its lower-case form in the class
            # a class that holds both forms of each of its letters, such as
            # [0-9A-Z_a-z], matches the same with or without (?i)
            upper_letters, lower_letters, other, case_property = _class_letters(body)
            if case_property:
                letter(dead=True, case_property=True)
            elif other or {u.lower() for u in upper_letters} != lower_letters:
                letter(any(u.lower() not in lower_letters for u in upper_letters))
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
            letter(c in _UPPER)
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

# Transformations that may sit between two t:lowercase. Dropping the first
# t:lowercase changes their input, so their output must not depend on the case
# of that input once the last t:lowercase folds it: urlDecode reads %4A and
# %4a alike. hexEncode, md5, base64Decode and the like do not qualify.
_SAFE_BETWEEN_LOWERCASE = _SAFE_AFTER_LOWERCASE | {"urldecode"}

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
    changes the value beyond removing characters, or one between two
    t:lowercase depends on the case of its input, so (?i) is not equivalent.
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
            between = names[positions[0] + 1:positions[-1]]
            after = names[positions[-1] + 1:]
            alters = (
                any(t not in _SAFE_AFTER_LOWERCASE for t in after)
                or any(t not in _SAFE_BETWEEN_LOWERCASE for t in between)
            )
            coverage, upper = _scan(d["operator_argument"])
            yield ruleid, lowered, coverage, _reads_value(chain, n), alters, upper
