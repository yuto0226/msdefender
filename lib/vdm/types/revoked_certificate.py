"""Lossless parser and concise renderer for REVOKED_CERTIFICATE (0x6C)."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Final, Literal

from ..core import DisplaySection, FamilySpec, FormatResult
from ..recid import RecIdTail, parse_recid_tail
from ._certificate_key import parse_certificate_key

REVOKED_CERTIFICATE_TYPE: Final = 0x6C
POLICY_TRAILER_SIZE: Final = 12
FILETIME_EPOCH: Final = datetime(1601, 1, 1, tzinfo=UTC)
SKIP_SIGNED_FILE_GATE_FLAG: Final = 0x00000001

_KEY_TYPES = MappingProxyType({1: "HASH", 2: "BY", 3: "TO", 4: "BADHASH", 5: "TEAMID"})


@dataclass(frozen=True, slots=True)
class RevokedCertificate:
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
    filetime_raw: bytes
    filetime: int
    timestamp_utc: datetime | None
    timestamp_error: str | None
    revoke_flags_raw: bytes
    revoke_flags: int
    recid_tail_raw: bytes
    recid_tail: RecIdTail | None

    @property
    def skips_signed_file_gate(self) -> bool:
        return bool(self.revoke_flags & SKIP_SIGNED_FILE_GATE_FLAG)

    @property
    def unknown_flag_bits(self) -> int:
        return self.revoke_flags & ~SKIP_SIGNED_FILE_GATE_FLAG


def _filetime_to_utc(value: int) -> tuple[datetime | None, str | None]:
    if value == 0:
        return None, None
    try:
        # datetime stops at microseconds; the exact 100 ns value remains in
        # filetime/filetime_raw even when this presentation value truncates.
        microseconds = value // 10
        timestamp = FILETIME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, ValueError) as exc:
        return None, str(exc)
    return timestamp, None


def parse_revoked_certificate(payload: bytes) -> RevokedCertificate:
    if len(payload) < 2:
        raise ValueError(
            f"truncated REVOKED_CERTIFICATE key_len: need 2 bytes, have {len(payload)}"
        )

    key_len = int.from_bytes(payload[:2], "little")
    if key_len < 2:
        raise ValueError(
            f"invalid REVOKED_CERTIFICATE key_len: need at least 2, have {key_len}"
        )
    key_end = 2 + key_len
    if key_end > len(payload):
        raise ValueError(
            "truncated REVOKED_CERTIFICATE key_data: "
            f"need {key_len} bytes, have {len(payload) - 2}"
        )

    trailer_end = key_end + POLICY_TRAILER_SIZE
    if trailer_end > len(payload):
        raise ValueError(
            "truncated REVOKED_CERTIFICATE policy trailer: "
            f"need {POLICY_TRAILER_SIZE} bytes, have {len(payload) - key_end}"
        )

    key_data = payload[2:key_end]
    key = parse_certificate_key(key_data)
    filetime_raw = payload[key_end : key_end + 8]
    filetime = int.from_bytes(filetime_raw, "little")
    timestamp_utc, timestamp_error = _filetime_to_utc(filetime)
    revoke_flags_raw = payload[key_end + 8 : trailer_end]
    recid_tail_raw = payload[trailer_end:]

    return RevokedCertificate(
        raw=payload,
        key_len=key_len,
        key_data=key_data,
        mode=key.mode,
        key_type=key.key_type,
        prefix=key.prefix,
        prefix_raw=key.prefix_raw,
        key_material_raw=key.material_raw,
        key_text=key.text,
        text_raw=key.text_raw,
        terminator_raw=key.terminator_raw,
        string_trailing_raw=key.trailing_raw,
        decode_error=key.decode_error,
        filetime_raw=filetime_raw,
        filetime=filetime,
        timestamp_utc=timestamp_utc,
        timestamp_error=timestamp_error,
        revoke_flags_raw=revoke_flags_raw,
        revoke_flags=int.from_bytes(revoke_flags_raw, "little"),
        recid_tail_raw=recid_tail_raw,
        recid_tail=parse_recid_tail(recid_tail_raw),
    )


def _certificate_key_rows(parsed: RevokedCertificate) -> tuple[tuple[str, str], ...]:
    label = _KEY_TYPES.get(parsed.key_type)
    key_type = f"0x{parsed.key_type:02x}"
    if label is not None:
        key_type += f" ({label})"
    rows = [
        ("key_len", f"{parsed.key_len} B"),
        ("mode", parsed.mode),
        ("key_type", key_type),
    ]
    if parsed.mode == "binary":
        rows.append(("key_material_raw", parsed.key_material_raw.hex(" ") or "(empty)"))
    else:
        rows.append(("prefix", parsed.prefix or "(none; defaults to TO)"))
        if parsed.key_text is not None:
            rows.append(("key_text", json.dumps(parsed.key_text, ensure_ascii=False)))
        else:
            rows.extend(
                (
                    ("decode_error", f"invalid UTF-16LE: {parsed.decode_error}"),
                    ("text_raw", parsed.text_raw.hex(" ") or "(empty)"),
                )
            )
        rows.append(("terminator", "NUL" if parsed.terminator_raw else "not present"))
        if parsed.string_trailing_raw:
            rows.append(("string_trailing_len", f"{len(parsed.string_trailing_raw)} B"))
    return tuple(rows)


def _record_identity_rows(tail: RecIdTail) -> tuple[tuple[str, str], ...]:
    rows = [
        ("recid_tail_len", f"{len(tail.raw)} B"),
        ("object_length_limit", f"{tail.length_limit} B"),
        ("effective_object_len", f"{len(tail.object_raw)} B"),
        ("object", "present" if tail.has_object else "absent"),
    ]
    if tail.trailing_raw:
        rows.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
    return tuple(rows)


def render_revoked_certificate(parsed: RevokedCertificate) -> FormatResult:
    if parsed.filetime == 0:
        timestamp_rows = [("timestamp_filetime", "0 (no lower-bound effect)")]
    else:
        timestamp_rows = [("timestamp_filetime", f"0x{parsed.filetime:016x}")]
        if parsed.timestamp_utc is not None:
            timestamp_rows.append(
                (
                    "timestamp_utc",
                    parsed.timestamp_utc.isoformat().replace("+00:00", "Z"),
                )
            )
        else:
            timestamp_rows.append(("timestamp_utc", "out of range"))
        if parsed.timestamp_error is not None:
            timestamp_rows.append(("timestamp_note", parsed.timestamp_error))

    policy_rows = [
        *timestamp_rows,
        ("revoke_flags", f"0x{parsed.revoke_flags:08x}"),
        (
            "signed_file_gate",
            "skipped (bit 0 set)"
            if parsed.skips_signed_file_gate
            else "not skipped when report policy is enforced (bit 0 clear)",
        ),
    ]
    if parsed.unknown_flag_bits:
        policy_rows.append(("unknown_flag_bits", f"0x{parsed.unknown_flag_bits:08x}"))

    sections = [
        DisplaySection("Certificate Key", rows=_certificate_key_rows(parsed)),
        DisplaySection("Revocation Policy", rows=tuple(policy_rows)),
    ]
    if parsed.recid_tail is not None:
        sections.append(
            DisplaySection(
                "Record Identity", rows=_record_identity_rows(parsed.recid_tail)
            )
        )
    return FormatResult(sections=tuple(sections))


SPEC = FamilySpec(
    REVOKED_CERTIFICATE_TYPE,
    "REVOKED_CERTIFICATE",
    parse_revoked_certificate,
    render_revoked_certificate,
)
