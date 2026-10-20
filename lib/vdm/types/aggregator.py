"""Lossless AAGGREGATOR envelopes, verified against mpengine 1.443.903.0."""

from dataclasses import dataclass
from functools import partial
from typing import Final, Literal

from ..condition import (
    And,
    AtLeast,
    Atom,
    Const,
    Expr,
    Not,
    Or,
    negate,
    render_yara_like,
)
from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
    SemanticJSONValue,
)
from ..pattern_codec import PATTERN_DECODING_TABLE

AAGGREGATOR_TYPE: Final = 0x96
AAGGREGATOREX_TYPE: Final = 0xE7
_FAMILY_NAMES: Final = {
    AAGGREGATOR_TYPE: "AAGGREGATOR",
    AAGGREGATOREX_TYPE: "AAGGREGATOREX",
}


@dataclass(frozen=True, slots=True)
class AggregatorPayload:
    """Wire bytes and byte decoding, without claiming expression semantics.

    Unknown flag bits cause an early successful skip in both receivers, before
    length validation. Such records retain available body slices even if their
    declared lengths exceed the payload; decoded_sig_data is then unavailable.
    """

    raw: bytes
    type_byte: int
    flags: int
    name_len: int
    sig_len: int
    name: bytes
    sig_data: bytes
    trailing: bytes
    decoded_sig_data: bytes | None

    @property
    def fuzzy(self) -> bool:
        return bool(self.flags & 1)

    @property
    def unknown_flag_bits(self) -> int:
        return self.flags & 0xFE

    @property
    def receiver_ignored(self) -> bool:
        return bool(self.unknown_flag_bits)

    @property
    def body_complete(self) -> bool:
        return 4 + self.name_len + self.sig_len <= len(self.raw)


AggregatorIssueCode = Literal[
    "receiver_ignored",
    "source_marker",
    "empty_expression",
    "empty_operand",
    "unbalanced_parentheses",
    "operand_too_long",
    "unexpected_token",
]


@dataclass(frozen=True, slots=True)
class AggregatorSemanticIssue:
    """A boundary of the verified subset, not necessarily engine rejection."""

    code: AggregatorIssueCode
    offset: int
    message: str


@dataclass(frozen=True, slots=True)
class AggregatorCondition:
    """Semantic interpretation, separate from the lossless wire payload."""

    expression: Expr | None
    issue: AggregatorSemanticIssue | None = None

    @property
    def semantic_status(self) -> Literal["verified_subset", "unsupported", "ignored"]:
        if self.issue is None:
            return "verified_subset"
        return "ignored" if self.issue.code == "receiver_ignored" else "unsupported"


class _AggregatorParseError(Exception):
    def __init__(self, code: AggregatorIssueCode, offset: int, message: str):
        self.issue = AggregatorSemanticIssue(code, offset, message)


def _strip_literal_parentheses(source: bytes) -> bytes:
    """Apply AddSignature's confirmed innermost literal-group rewrite."""
    normalized = source
    while True:
        stack: list[int] = []
        changed = False
        for closing, byte in enumerate(normalized):
            if byte == ord("("):
                stack.append(closing)
            elif byte == ord(")"):
                if not stack:
                    return normalized
                opening = stack.pop()
                inner = normalized[opening + 1 : closing]
                if b"&" not in inner and b"|" not in inner:
                    normalized = (
                        normalized[:opening] + inner + normalized[closing + 1 :]
                    )
                    changed = True
                    break
        if not changed:
            return normalized


def interpret_aggregator(parsed: AggregatorPayload) -> AggregatorCondition:
    """Decode the verified expression grammar without changing wire parsing."""
    if parsed.decoded_sig_data is None:
        return AggregatorCondition(
            None,
            AggregatorSemanticIssue(
                "receiver_ignored",
                0,
                "receiver ignored the record before expression parsing",
            ),
        )
    source = parsed.decoded_sig_data.split(b"\0", 1)[0]
    if b"#" in source:
        return AggregatorCondition(
            None,
            AggregatorSemanticIssue(
                "source_marker", source.index(b"#"), "source marker '#' is unsupported"
            ),
        )
    if not source:
        return AggregatorCondition(
            None, AggregatorSemanticIssue("empty_expression", 0, "expression is empty")
        )
    source = _strip_literal_parentheses(source)
    if not source:
        return AggregatorCondition(
            None,
            AggregatorSemanticIssue(
                "empty_expression", 0, "expression is empty after parenthesis rewrite"
            ),
        )

    # The engine's operators share precedence and fold left-to-right. Building
    # binary nodes (rather than smart constructors) retains that grouping.
    cursor = 0

    def parse_operand() -> Expr:
        nonlocal cursor
        if cursor >= len(source):
            raise _AggregatorParseError("empty_operand", cursor, "expected an operand")
        if source[cursor] == ord("("):
            opening = cursor
            cursor += 1
            if cursor < len(source) and source[cursor] == ord(")"):
                raise _AggregatorParseError(
                    "empty_operand", cursor, "empty parenthesized expression"
                )
            expression = parse_expression(in_group=True)
            if cursor >= len(source) or source[cursor] != ord(")"):
                raise _AggregatorParseError(
                    "unbalanced_parentheses",
                    opening,
                    "opening parenthesis has no closing pair",
                )
            cursor += 1
            return expression
        if source[cursor] == ord(")"):
            raise _AggregatorParseError(
                "empty_operand", cursor, "expected an operand before ')' "
            )

        start = cursor
        while cursor < len(source) and source[cursor] not in b"&|()":
            cursor += 1
        token = source[start:cursor]
        if len(token) > 63:
            raise _AggregatorParseError(
                "operand_too_long",
                start,
                f"operand is {len(token)} bytes; maximum is 63",
            )
        if not token or token == b"!":
            raise _AggregatorParseError("empty_operand", start, "operand is empty")
        negated = token.startswith(b"!")
        identifier = token[1:] if negated else token
        if not identifier:
            raise _AggregatorParseError(
                "empty_operand", start, "negated operand has no name"
            )
        atom = Atom(identifier.decode("latin-1"))
        return negate(atom) if negated else atom

    def parse_expression(*, in_group: bool) -> Expr:
        nonlocal cursor
        left = parse_operand()
        while cursor < len(source) and source[cursor] != ord(")"):
            operator = source[cursor]
            if operator not in (ord("&"), ord("|")):
                raise _AggregatorParseError(
                    "unexpected_token",
                    cursor,
                    f"expected '&', '|', or ')', found {chr(operator)!r}",
                )
            cursor += 1
            right = parse_operand()
            left = And((left, right)) if operator == ord("&") else Or((left, right))
        if not in_group and cursor < len(source) and source[cursor] == ord(")"):
            raise _AggregatorParseError(
                "unbalanced_parentheses",
                cursor,
                "closing parenthesis has no opening pair",
            )
        return left

    try:
        expression = parse_expression(in_group=False)
        if cursor != len(source):
            raise _AggregatorParseError(
                "unbalanced_parentheses",
                cursor,
                "closing parenthesis has no opening pair",
            )
        return AggregatorCondition(expression)
    except _AggregatorParseError as error:
        return AggregatorCondition(None, error.issue)


def _expression_ast(expression: Expr) -> SemanticJSONValue:
    """Serialize the verified condition nodes as a tagged JSON AST object."""
    if isinstance(expression, Const):
        return JSONObject((("type", "const"), ("value", expression.value)))
    if isinstance(expression, Atom):
        return JSONObject((("type", "atom"), ("identifier", expression.identifier)))
    if isinstance(expression, AtLeast):
        return JSONObject(
            (
                ("type", "at_least"),
                ("count", expression.count),
                (
                    "atoms",
                    JSONArray(
                        tuple(_expression_ast(atom) for atom in expression.atoms)
                    ),
                ),
                ("selector", expression.selector),
            )
        )
    if isinstance(expression, And | Or):
        return JSONObject(
            (
                ("type", "and" if isinstance(expression, And) else "or"),
                (
                    "terms",
                    JSONArray(
                        tuple(_expression_ast(term) for term in expression.terms)
                    ),
                ),
            )
        )
    if isinstance(expression, Not):
        return JSONObject((("type", "not"), ("term", _expression_ast(expression.term))))
    raise TypeError(f"unsupported expression {type(expression).__name__}")


def export_aggregator_semantics(parsed: AggregatorPayload) -> RuleSemantics:
    condition = interpret_aggregator(parsed)
    issue = condition.issue
    return RuleSemantics(
        status=(
            "confirmed_subset"
            if issue is None
            else "ignored"
            if issue.code == "receiver_ignored"
            else "unsupported"
        ),
        representation="boolean_expr.ast.v1",
        data=None
        if condition.expression is None
        else _expression_ast(condition.expression),
        evidence=("mpengine 1.443.903.0 AddSignature expression subset",),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                issue.code,
                issue.message,
                (("offset", issue.offset),),
            ),
        )
        if issue is not None
        else (),
    )


def parse_aggregator(payload: bytes, *, type_byte: int) -> AggregatorPayload:
    """Parse either receiver envelope; ValueError denotes malformed input.

    For known flags only, a truncated name/signature is a receiver error
    (0x800C). Unknown flags are retained as an ignored record, matching the
    receiver's return 0 before checking those lengths. Downstream expression
    validation, name registration and RecID creation are outside this parser.
    """
    if type_byte not in _FAMILY_NAMES:
        raise ValueError(f"unsupported aggregator type {type_byte:#04x}")
    if len(payload) < 4:
        raise ValueError("truncated aggregator header: need 4 bytes")

    flags, name_len = payload[:2]
    sig_len = int.from_bytes(payload[2:4], "little")
    name_end = 4 + name_len
    sig_end = name_end + sig_len
    ignored = bool(flags & 0xFE)
    if not ignored:
        if name_end > len(payload):
            raise ValueError("truncated aggregator name")
        if sig_end > len(payload):
            raise ValueError("truncated aggregator sig_data")

    sig_data = payload[name_end:sig_end]
    decoded = None
    if not ignored:
        decoded = (
            sig_data.translate(PATTERN_DECODING_TABLE)
            if type_byte == AAGGREGATOREX_TYPE
            else sig_data
        )
    return AggregatorPayload(
        raw=payload,
        type_byte=type_byte,
        flags=flags,
        name_len=name_len,
        sig_len=sig_len,
        name=payload[4:name_end],
        sig_data=sig_data,
        trailing=payload[sig_end:],
        decoded_sig_data=decoded,
    )


def _preview(data: bytes) -> str:
    shown = data[:32].hex(" ")
    suffix = " ..." if len(data) > 32 else ""
    return f"{len(data)} B [{shown}{suffix}]"


def _text_preview(data: bytes) -> str:
    # Escape control characters, ANSI sequences and arbitrary bytes for loggers.
    shown = ascii(data[:160].decode("latin-1"))
    return shown + (" ..." if len(data) > 160 else "")


def render_aggregator(parsed: AggregatorPayload) -> FormatResult:
    """Render bounded sections; byte decoding does not imply a validated AST."""
    flags = f"{parsed.flags:#04x}"
    if parsed.unknown_flag_bits:
        flags += f", unknown={parsed.unknown_flag_bits:#04x}"
    sections = [
        DisplaySection(
            "Aggregator Envelope",
            rows=(
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("flags", flags),
                (
                    "terminal_pair_metadata",
                    "fuzzy (matching effect unverified)" if parsed.fuzzy else "none",
                ),
                (
                    "receiver_status",
                    "ignored: unknown flag bits (return 0)"
                    if parsed.receiver_ignored
                    else "envelope accepted; downstream validation not evaluated",
                ),
                ("name_len", str(parsed.name_len)),
                ("sig_len", str(parsed.sig_len)),
                ("body_complete", str(parsed.body_complete).lower()),
                ("name_preview", _text_preview(parsed.name)),
                *(
                    (("sig_data_raw", _preview(parsed.sig_data)),)
                    if parsed.decoded_sig_data is None
                    else ()
                ),
                ("trailing_len", str(len(parsed.trailing))),
            ),
        ),
    ]
    if parsed.decoded_sig_data is None:
        sections.append(
            DisplaySection(
                "Aggregator Expression",
                rows=(("decode_status", "not evaluated: receiver ignores record"),),
            )
        )
    else:
        decoded = parsed.decoded_sig_data
        # AddSignature copies sig_len bytes, appends NUL, then uses C strings.
        # Preserve bytes following an embedded NUL separately from its text view.
        expression = decoded.split(b"\0", 1)[0]
        condition = interpret_aggregator(parsed)
        sections.append(
            DisplaySection(
                "Aggregator Expression",
                rows=(
                    (
                        "byte_decoding",
                        "pattern substitution table (mpengine 1.443.903.0)"
                        if parsed.type_byte == AAGGREGATOREX_TYPE
                        else "none: plain expression bytes",
                    ),
                    *(
                        (("expression_preview", _text_preview(expression)),)
                        if not expression or expression.decode("latin-1").isprintable()
                        else (("decoded_raw", _preview(decoded)),)
                    ),
                    (
                        "post_nul_length",
                        str(len(decoded) - len(expression) - (b"\0" in decoded)),
                    ),
                    ("semantic_status", condition.semantic_status),
                    *(
                        (("condition", render_yara_like(condition.expression)),)
                        if condition.expression is not None
                        else ()
                    ),
                    *(
                        (
                            (
                                "semantic_issue",
                                f"{condition.issue.code} at byte {condition.issue.offset}: {condition.issue.message}",
                            ),
                        )
                        if condition.issue is not None
                        else ()
                    ),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


AGGREGATOR_SPECS = (
    FamilySpec(
        AAGGREGATOR_TYPE,
        "AAGGREGATOR",
        partial(parse_aggregator, type_byte=AAGGREGATOR_TYPE),
        render_aggregator,
        semantic_exporter=export_aggregator_semantics,
    ),
    FamilySpec(
        AAGGREGATOREX_TYPE,
        "AAGGREGATOREX",
        partial(parse_aggregator, type_byte=AAGGREGATOREX_TYPE),
        render_aggregator,
        semantic_exporter=export_aggregator_semantics,
    ),
)
