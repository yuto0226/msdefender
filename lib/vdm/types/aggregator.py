"""Lossless AAGGREGATOR envelopes, verified against mpengine 1.443.903.0."""

from dataclasses import dataclass
from functools import partial
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult
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
    flags = f"{parsed.flags:#04x} (fuzzy={str(parsed.fuzzy).lower()})"
    if parsed.unknown_flag_bits:
        flags += f", unknown={parsed.unknown_flag_bits:#04x}"
    sections = [
        DisplaySection(
            "Aggregator Envelope",
            rows=(
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("flags", flags),
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
                    ("semantic_status", "unavailable: expression grammar not decoded"),
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
    ),
    FamilySpec(
        AAGGREGATOREX_TYPE,
        "AAGGREGATOREX",
        partial(parse_aggregator, type_byte=AAGGREGATOREX_TYPE),
        render_aggregator,
    ),
)
