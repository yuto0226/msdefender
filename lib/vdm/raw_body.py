"""Strict callback-19 byte-search language and ordered runtime-view recipes.

No generic regex engine, HTTP decoder, YARA runtime or post-match policy runs
here. Dot includes all 256 bytes; anchors use the observed byte line boundaries.
"""

from collections.abc import Iterator
from dataclasses import dataclass

LINE_BOUNDARIES = frozenset((0x0A, 0x0C, 0x0D, 0x85))
_META = b".^$|[]{}()*+?\\"
_HEX = b"0123456789abcdefABCDEF"
# YARA4.5.4 lexer keywords and integer-function tokens; no runtime dependency.
# https://github.com/VirusTotal/yara/blob/v4.5.4/libyara/lexer.l
_YARA_RESERVED = frozenset(
    [
        "private",
        "global",
        "rule",
        "meta",
        "strings",
        "ascii",
        "wide",
        "xor",
        "base64",
        "base64wide",
        "fullword",
        "nocase",
        "condition",
        "true",
        "false",
        "not",
        "and",
        "or",
        "at",
        "in",
        "of",
        "them",
        "for",
        "all",
        "any",
        "none",
        "entrypoint",
        "filesize",
        "matches",
        "contains",
        "startswith",
        "endswith",
        "icontains",
        "istartswith",
        "iendswith",
        "iequals",
        "import",
        "defined",
        "include",
    ]
) | frozenset(
    f"{unsigned}int{bits}{endian}"
    for unsigned in ("", "u")
    for bits in (8, 16, 32)
    for endian in ("", "be")
)


class UnsupportedRawBodyPattern(ValueError):
    """Outside the bounded byte grammar, not necessarily invalid Boost syntax."""


class UnsupportedRawBodySubject(ValueError):
    """A selected runtime view lacks sufficient physically available bytes."""


@dataclass(frozen=True, slots=True)
class RawBodyToken:
    """A literal byte or all-byte dot, with only observed bounded repeats."""

    value: int | None
    minimum: int = 1
    maximum: int = 1

    def __post_init__(self) -> None:
        if self.value is not None and (
            type(self.value) is not int or not 0 <= self.value <= 255
        ):
            raise ValueError("literal must be uint8, or None for all-byte dot")
        if type(self.minimum) is not int or type(self.maximum) is not int:
            raise TypeError("repeat bounds must be integers")
        bounds = self.minimum, self.maximum
        if (
            bounds == (1, 1)
            or self.value is None
            and bounds in ((32, 32), (0, 8))
            or self.value == 0xCC
            and bounds == (1, 8)
        ):
            return
        raise UnsupportedRawBodyPattern(
            "repeat outside the observed bounded constructs"
        )


@dataclass(frozen=True, slots=True)
class RawBodyBranch:
    tokens: tuple[RawBodyToken, ...]
    start_anchor: bool = False
    end_anchor: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.tokens, tuple) or not self.tokens:
            raise UnsupportedRawBodyPattern("a nonempty immutable branch is required")
        if any(not isinstance(t, RawBodyToken) for t in self.tokens):
            raise TypeError("expected strict byte tokens")
        if type(self.start_anchor) is not bool or type(self.end_anchor) is not bool:
            raise TypeError("anchor flags must be bool")
        if not sum(t.minimum for t in self.tokens):
            raise UnsupportedRawBodyPattern("nullable branches are outside the subset")
        if any(
            t.value is None and (t.minimum, t.maximum) != (1, 1)
            for t in (self.tokens[0], self.tokens[-1])
        ):
            raise UnsupportedRawBodyPattern(
                "bounded dot jumps must be internal to a branch"
            )
        if (self.start_anchor or self.end_anchor) and any(
            t.value is None
            or t.minimum != 1
            or t.maximum != 1
            or t.value in LINE_BOUNDARIES
            for t in self.tokens
        ):
            raise UnsupportedRawBodyPattern(
                "anchors require fixed literals without line-boundary bytes"
            )


@dataclass(frozen=True, slots=True)
class RawBodyPattern:
    branches: tuple[RawBodyBranch, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.branches, tuple) or not self.branches:
            raise UnsupportedRawBodyPattern(
                "nonempty immutable alternatives are required"
            )
        if any(not isinstance(b, RawBodyBranch) for b in self.branches):
            raise TypeError("expected strict branches")


def compile_raw_body_pattern(effective_pattern: bytes) -> RawBodyPattern:
    """Fully consume the strict byte grammar; never invoke a regex backend.

    Supports printable ASCII literals, hex escapes, escaped regex punctuation,
    all-byte dot, top-level alternatives and the three observed repeat forms.
    Anchors accept only fixed literal branches without boundary bytes. Input
    excludes the constructor's first NUL; unsupported is not compile-invalid.
    """
    if not isinstance(effective_pattern, bytes):
        raise TypeError("effective pattern must be bytes")
    branches = []
    tokens = []
    start = end = False
    offset = 0
    while offset < len(effective_pattern):
        byte = effective_pattern[offset]
        if byte == 124:
            branches.append(RawBodyBranch(tuple(tokens), start, end))
            tokens, start, end = [], False, False
            offset += 1
            continue
        if end:
            raise UnsupportedRawBodyPattern("end anchor must finish its branch")
        if byte == 94 and not tokens and not start:
            start = True
            offset += 1
            continue
        if byte == 36:
            end = True
            offset += 1
            continue
        if effective_pattern[offset : offset + 2] == b"\\x":
            digits = effective_pattern[offset + 2 : offset + 4]
            if len(digits) != 2 or not all(c in _HEX for c in digits):
                raise UnsupportedRawBodyPattern("invalid bounded hex token")
            value = bytes.fromhex(digits.decode("ascii"))[0]
            offset += 4
        elif byte == 92:
            if (
                offset + 1 >= len(effective_pattern)
                or effective_pattern[offset + 1] not in _META
            ):
                raise UnsupportedRawBodyPattern("unsupported escape")
            value = effective_pattern[offset + 1]
            offset += 2
        elif byte == 46:
            value = None
            offset += 1
        elif 32 <= byte <= 126 and byte not in _META:
            value = byte
            offset += 1
        else:
            raise UnsupportedRawBodyPattern("outside strict byte grammar")
        low = high = 1
        if effective_pattern[offset : offset + 1] == b"{":
            close = effective_pattern.find(b"}", offset)
            spelling = effective_pattern[offset : close + 1] if close >= 0 else b""
            if value is None and spelling in (b"{32}", b"{0,8}"):
                low, high = (32, 32) if spelling == b"{32}" else (0, 8)
            elif value == 0xCC and spelling == b"{1,8}":
                low, high = 1, 8
            else:
                raise UnsupportedRawBodyPattern("unsupported repeat")
            offset = close + 1
        tokens.append(RawBodyToken(value, low, high))
    branches.append(RawBodyBranch(tuple(tokens), start, end))
    return RawBodyPattern(tuple(branches))


def _candidate_starts(
    subject: bytes, prefix: bytes, minimum_width: int
) -> Iterator[int]:
    if not prefix:
        yield from range(len(subject) - minimum_width + 1)
        return
    position = subject.find(prefix)
    while 0 <= position <= len(subject) - minimum_width:
        yield position
        position = subject.find(prefix, position + 1)


def search_raw_body_bytes(pattern: RawBodyPattern, subject: bytes) -> bool:
    """Boolean search on the exact supplied span, including embedded NUL.

    This does not reproduce native allocation failures or caught exceptions.
    Existence is sufficient: captures, greedy choice and RecID policy are not
    exposed by this local predicate.
    """
    if not isinstance(pattern, RawBodyPattern) or not isinstance(subject, bytes):
        raise TypeError("expected a strict pattern and exact subject bytes")
    size = len(subject)
    for branch in pattern.branches:
        if all(
            t.value is not None and t.minimum == t.maximum == 1 for t in branch.tokens
        ):
            literal = bytes(t.value for t in branch.tokens)
            position = subject.find(literal)
            while position >= 0:
                finish = position + len(literal)
                if (
                    not branch.start_anchor
                    or position == 0
                    or subject[position - 1] in LINE_BOUNDARIES
                ) and (
                    not branch.end_anchor
                    or finish == size
                    or subject[finish] in LINE_BOUNDARIES
                ):
                    return True
                position = subject.find(literal, position + 1)
            continue
        prefix = bytearray()
        for token in branch.tokens:
            if token.value is None or token.minimum != 1 or token.maximum != 1:
                break
            prefix.append(token.value)
        minimum_width = sum(t.minimum for t in branch.tokens)
        for start in _candidate_starts(subject, bytes(prefix), minimum_width):
            # Preserve all legal end positions for one start; memory depends on
            # bounded pattern width, not total body length or number of starts.
            positions = {start}
            for token in branch.tokens:
                following = set()
                for position in positions:
                    for count in range(
                        token.minimum, min(token.maximum, size - position) + 1
                    ):
                        if (
                            token.value is None
                            or subject[position : position + count]
                            == bytes([token.value]) * count
                        ):
                            following.add(position + count)
                positions = following
                if not positions:
                    break
            if positions:
                return True
    return False


def render_raw_body_yara(pattern: RawBodyPattern, rule_name: str) -> str:
    """Render the same explicit-span Boolean predicate, without importing YARA."""
    if not isinstance(pattern, RawBodyPattern):
        raise TypeError("expected a strict pattern")
    if (
        not isinstance(rule_name, str)
        or not rule_name.isascii()
        or not 1 <= len(rule_name) <= 128
        or not (rule_name[0].isalpha() or rule_name[0] == "_")
        or not all(c.isalnum() or c == "_" for c in rule_name)
        or rule_name in _YARA_RESERVED
    ):
        raise ValueError(
            "expected a legal ASCII YARA identifier of at most128 characters"
        )
    strings, conditions = [], []
    for index, branch in enumerate(pattern.branches):
        atoms = []
        for token in branch.tokens:
            low, high = token.minimum, token.maximum
            if token.value is None:
                atoms.append(
                    "??"
                    if low == high == 1
                    else f"[{low}]"
                    if low == high
                    else f"[{low}-{high}]"
                )
            elif low == high == 1:
                atoms.append(f"{token.value:02X}")
            else:
                atoms.append(
                    "( "
                    + " | ".join(
                        " ".join([f"{token.value:02X}"] * count)
                        for count in range(low, high + 1)
                    )
                    + " )"
                )
        ident = f"b{index}"
        strings.append(f"${ident} = {{ " + " ".join(atoms) + " }")
        tests = []
        if branch.start_anchor:
            previous = " or ".join(
                f"uint8(@{ident}[i] - 1) == {v}" for v in sorted(LINE_BOUNDARIES)
            )
            tests.append(f"(@{ident}[i] == 0 or {previous})")
        if branch.end_anchor:
            following = " or ".join(
                f"uint8(@{ident}[i] + !{ident}[i]) == {v}"
                for v in sorted(LINE_BOUNDARIES)
            )
            tests.append(f"(@{ident}[i] + !{ident}[i] == filesize or {following})")
        conditions.append(
            f"for any i in (1..#{ident}) : (" + " and ".join(tests) + ")"
            if tests
            else f"${ident}"
        )
    return (
        f"rule {rule_name} {{\n strings:\n  "
        + "\n  ".join(strings)
        + "\n condition:\n  "
        + " or ".join(f"({c})" for c in conditions)
        + "\n}\n"
    )


@dataclass(frozen=True, slots=True)
class RawBodyView:
    """Resolved view pointer: u32 size+4 and physical buffer pointer+8."""

    buffer: bytes | None
    logical_size: int

    def __post_init__(self) -> None:
        if self.buffer is not None and not isinstance(self.buffer, bytes):
            raise TypeError("physical buffer must be bytes or actual NULL")
        if (
            type(self.logical_size) is not int
            or not 0 <= self.logical_size <= 0xFFFFFFFF
        ):
            raise ValueError("logical size must be uint32")


@dataclass(frozen=True, slots=True)
class RawBodyQuery:
    """Recipe-local query; global-vector and ProcessMatchedSignature are external."""

    metadata_offset: int
    policy_byte: int
    subject: bytes

    def __post_init__(self) -> None:
        if (
            type(self.metadata_offset) is not int
            or type(self.policy_byte) is not int
            or (self.metadata_offset, self.policy_byte) not in ((0x30, 0), (0x38, 1))
        ):
            raise ValueError("expected the original metadata slot/policy pair")
        if not isinstance(self.subject, bytes) or not self.subject:
            raise ValueError("selected runtime query requires nonempty physical bytes")


def project_raw_body_queries(
    view30: RawBodyView | None, view38: RawBodyView | None
) -> tuple[RawBodyQuery, ...]:
    """Keep independent +0x30 then +0x38 views, full buffer ranges and policy0/1.

    NULL view/buffer or size0 skips that view; insufficient selected physical
    storage is unsupported, not mismatch. No HTTP-role, decoding, concatenation
    or SSL framing is inferred. Pattern-vector presence remains an outer gate.
    """
    queries = []
    for view, offset, policy in ((view30, 0x30, 0), (view38, 0x38, 1)):
        if view is None:
            continue
        if not isinstance(view, RawBodyView):
            raise TypeError("expected resolved body views or actual NULL")
        if view.buffer is None or view.logical_size == 0:
            continue
        if len(view.buffer) < view.logical_size:
            raise UnsupportedRawBodySubject(
                "selected full-buffer span lacks readable bytes"
            )
        queries.append(RawBodyQuery(offset, policy, view.buffer[: view.logical_size]))
    return tuple(queries)
