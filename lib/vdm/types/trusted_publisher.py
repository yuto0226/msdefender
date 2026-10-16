"""Lossless TRUSTED_PUBLISHER framing and bounded key interpretation."""

import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult
from ..recid import RecIdTail, parse_recid_tail

TRUSTED_PUBLISHER_TYPE: Final = 0x70

_KEY_TYPES = MappingProxyType({1: "HASH", 2: "BY", 3: "TO", 4: "BADHASH", 5: "TEAMID"})
_PREFIXES = tuple(
    (label + ":", key_type)
    for key_type, label in (
        (1, "HASH"),
        (4, "BADHASH"),
        (2, "BY"),
        (3, "TO"),
        (5, "TEAMID"),
    )
)


@dataclass(frozen=True, slots=True)
class TrustedPublisher:
    raw: bytes
    key_len: int
    key_data: bytes
    mode: Literal["binary", "string"]
    key_type: int
    prefix: str | None
    prefix_raw: bytes
    key_material_raw: bytes
    key_text: str | None
    text_raw: bytes
    terminator_raw: bytes
    string_trailing_raw: bytes
    decode_error: str | None
    recid_tail_raw: bytes
    recid_tail: RecIdTail | None


def parse_trusted_publisher(payload: bytes) -> TrustedPublisher:
    """Parse the WORD-sized key and retain opaque or malformed key contents.

    Load at 0x18032039C rejects keys shorter than two bytes. Its string GetKey
    overload scans for NUL without a length; this parser stays within key_len.
    UTF-16LE is confirmed by wcsnicmp and the wide-string GetKey overload.
    """
    if len(payload) < 2:
        raise ValueError(
            f"truncated TRUSTED_PUBLISHER key_len: need 2 bytes, have {len(payload)}"
        )
    key_len = int.from_bytes(payload[:2], "little")
    if key_len < 2:
        raise ValueError(
            f"invalid TRUSTED_PUBLISHER key_len: need at least 2, have {key_len}"
        )
    key_end = 2 + key_len
    if key_end > len(payload):
        raise ValueError(
            "truncated TRUSTED_PUBLISHER key_data: "
            f"need {key_len} bytes, have {len(payload) - 2}"
        )

    key_data = payload[2:key_end]
    recid_tail_raw = payload[key_end:]
    mode = "binary" if key_data[0] < 0x20 else "string"
    key_type = key_data[0] if mode == "binary" else 3
    prefix = None
    prefix_raw = b""
    key_material_raw = key_data[1:] if mode == "binary" else key_data
    text_raw = b""
    terminator_raw = b""
    string_trailing_raw = b""
    key_text = None
    decode_error = None

    if mode == "string":
        # The engine compares only ASCII prefixes, case-insensitively. Compare
        # their raw UTF-16LE bytes so malformed later text remains lossless.
        for label, candidate_type in _PREFIXES:
            encoded = label.encode("utf-16le")
            if key_data[: len(encoded)].upper() == encoded:
                prefix = label[:-1]
                prefix_raw = key_data[: len(encoded)]
                key_material_raw = key_data[len(encoded) :]
                key_type = candidate_type
                break

        text_raw = key_data
        for offset in range(0, len(key_data) - 1, 2):
            if key_data[offset : offset + 2] == b"\0\0":
                text_raw = key_data[:offset]
                terminator_raw = key_data[offset : offset + 2]
                string_trailing_raw = key_data[offset + 2 :]
                break
        try:
            key_text = text_raw.decode("utf-16le")
        except UnicodeDecodeError as exc:
            decode_error = str(exc)

    # The signature hash covers payload[:key_end], excluding this RecID tail;
    # Load also ORs (key_end << 40) and 0x7000000000 into its CRC result. Key
    # material itself is not universally a digest (see both GetKey overloads).
    return TrustedPublisher(
        raw=payload,
        key_len=key_len,
        key_data=key_data,
        mode=mode,
        key_type=key_type,
        prefix=prefix,
        prefix_raw=prefix_raw,
        key_material_raw=key_material_raw,
        key_text=key_text,
        text_raw=text_raw,
        terminator_raw=terminator_raw,
        string_trailing_raw=string_trailing_raw,
        decode_error=decode_error,
        recid_tail_raw=recid_tail_raw,
        recid_tail=parse_recid_tail(recid_tail_raw),
    )


def render_trusted_publisher(parsed: TrustedPublisher) -> FormatResult:
    label = _KEY_TYPES.get(parsed.key_type)
    key_type = f"0x{parsed.key_type:02x}"
    if label is not None:
        key_type += f" ({label})"
    fields = (
        ("key_len", str(parsed.key_len)),
        ("mode", parsed.mode),
        ("key_type", key_type),
    )
    rows = list(fields)
    if parsed.mode == "binary":
        rows.append(("key_material_raw", parsed.key_material_raw.hex(" ") or "(empty)"))
    if parsed.mode == "string":
        rows.append(("prefix", parsed.prefix or "(none; defaults to TO)"))
        if parsed.key_text is not None:
            rows.append(("key_text", json.dumps(parsed.key_text, ensure_ascii=False)))
        else:
            rows.append(("decode_error", f"invalid UTF-16LE: {parsed.decode_error}"))
            rows.append(("text_raw", parsed.text_raw.hex(" ") or "(empty)"))
        rows.append(
            (
                "terminator",
                "NUL"
                if parsed.terminator_raw
                else "(missing within key_len; engine reads an unbounded string)",
            )
        )
        if parsed.string_trailing_raw:
            rows.append(("string_trailing_len", f"{len(parsed.string_trailing_raw)} B"))
    sections = [DisplaySection("Publisher key", rows=tuple(rows))]
    if parsed.recid_tail_raw:
        sections.append(
            DisplaySection(
                "RecID tail",
                rows=(("recid_tail_len", f"{len(parsed.recid_tail_raw)} B"),),
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    TRUSTED_PUBLISHER_TYPE,
    "TRUSTED_PUBLISHER",
    parse_trusted_publisher,
    render_trusted_publisher,
)
