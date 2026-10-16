"""Lossless AAGGREGATOR envelopes, verified against mpengine 1.443.903.0."""

from dataclasses import dataclass
from functools import partial
from typing import Final

from ..core import DisplaySection, FamilySpec, FormatResult

AAGGREGATOR_TYPE: Final = 0x96
AAGGREGATOREX_TYPE: Final = 0xE7
_FAMILY_NAMES: Final = {
    AAGGREGATOR_TYPE: "AAGGREGATOR",
    AAGGREGATOREX_TYPE: "AAGGREGATOREX",
}

# g_PatternDecodingTable @ 0x180DF1740. EX applies this substitution only to
# sig_data; the plain receiver performs no decoding. This is not DWORD XOR.
_PATTERN_DECODING_TABLE: Final = bytes.fromhex(
    "4b ba a3 c0 46 43 84 ed a8 97 3f 72 17 ad ef 54"
    "dd f9 21 64 42 f1 8c 49 68 76 77 fc 11 b2 74 d3"
    "dc 04 09 96 d4 0d f6 19 fb 35 7e 9f d1 e1 9d cc"
    "db 63 f5 30 94 40 7c f3 5d c7 aa e4 e6 14 67 6e"
    "d8 37 a2 b0 56 a6 51 df b9 85 39 15 9e 8d 3e 22"
    "ce fe 7a 0a c1 7d 9c 93 b3 13 08 2a 0c 3d 06 82"
    "60 9b bd 05 c4 24 1e 50 e5 01 4f 1c f4 8a 98 2c"
    "cd 3c 5e 6d 32 8f 2b 47 2f 1d a5 bb 25 b8 d7 b1"
    "65 91 58 c9 be 92 e8 8b 33 55 12 8e ea ab f8 26"
    "1f 71 1b 52 cb e2 e7 86 ae 62 31 fd af 02 d2 0e b7"
    "e3 83 48 16 cf d5 79 03 0f da b5 6f 4d 7b de 07 9a"
    "d9 a0 c8 27 a1 d0 c3 10 bf f7 61 18 eb 38 28 a9 5f"
    "66 c5 0b 95 53 5b 00 f0 7f 81 f2 6a d6 78 73 1a"
    "ac 89 a4 fa 44 36 b4 75 c2 23 bc 59 e9 29 ca 5a 41"
    "6b 34 70 4c ee b6 6c 87 3a 57 80 a7 99 ec 69 ff e0"
    "c6 4a 3b 4e 20 5c 2d 45 88 2e 90"
)


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
            sig_data.translate(_PATTERN_DECODING_TABLE)
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
