from dataclasses import dataclass
from typing import Final

from ..core import FamilySpec, FormatResult
from ..recid import RecIdTail, parse_recid_tail

FRIENDLYFILE_SHA256_TYPE: Final = 0xA0
SHA256_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class FriendlyFileSha256:
    raw: bytes
    sha256: bytes
    recid_tail: RecIdTail | None


def parse_friendlyfile_sha256(payload: bytes) -> FriendlyFileSha256:
    if len(payload) < SHA256_SIZE:
        raise ValueError(
            "truncated FRIENDLYFILE_SHA256 digest: "
            f"need {SHA256_SIZE} bytes, have {len(payload)}"
        )
    return FriendlyFileSha256(
        raw=payload,
        sha256=payload[:SHA256_SIZE],
        recid_tail=parse_recid_tail(payload[SHA256_SIZE:]),
    )


def render_friendlyfile_sha256(parsed: FriendlyFileSha256) -> FormatResult:
    fields = [
        ("sha256", parsed.sha256.hex()),
        ("digest_match", "exact 32-byte comparison"),
    ]
    if parsed.recid_tail is not None:
        tail = parsed.recid_tail
        fields.extend(
            (
                ("recid_tail_len", f"{len(tail.raw)} B"),
                ("object_length_limit", f"{tail.length_limit} B"),
                ("effective_object_len", f"{len(tail.object_raw)} B"),
                (
                    "object_registration",
                    "created"
                    if tail.has_object
                    else "suppressed: empty or leading NUL",
                ),
                ("lookup_tail_usage", "not read by FRIENDLYFILE lookup"),
            )
        )
        if tail.trailing_raw:
            fields.append(("trailing_len", f"{len(tail.trailing_raw)} B"))
    return FormatResult(fields=tuple(fields))


SPEC = FamilySpec(
    FRIENDLYFILE_SHA256_TYPE,
    "FRIENDLYFILE_SHA256",
    parse_friendlyfile_sha256,
    render_friendlyfile_sha256,
)
