from dataclasses import dataclass
from typing import Final

from ..core import FamilySpec, FormatResult

FRIENDLYFILE_SHA256_TYPE: Final = 0xA0
SHA256_SIZE: Final = 32


@dataclass(frozen=True, slots=True)
class FriendlyFileSha256:
    raw: bytes
    sha256: bytes
    recid_tail_raw: bytes


def parse_friendlyfile_sha256(payload: bytes) -> FriendlyFileSha256:
    if len(payload) < SHA256_SIZE:
        raise ValueError(
            "truncated FRIENDLYFILE_SHA256 digest: "
            f"need {SHA256_SIZE} bytes, have {len(payload)}"
        )
    return FriendlyFileSha256(
        raw=payload,
        sha256=payload[:SHA256_SIZE],
        recid_tail_raw=payload[SHA256_SIZE:],
    )


def render_friendlyfile_sha256(parsed: FriendlyFileSha256) -> FormatResult:
    fields = [("sha256", parsed.sha256.hex())]
    if parsed.recid_tail_raw:
        fields.append(("recid_tail_len", f"{len(parsed.recid_tail_raw)} B"))
    return FormatResult(fields=tuple(fields))


SPEC = FamilySpec(
    FRIENDLYFILE_SHA256_TYPE,
    "FRIENDLYFILE_SHA256",
    parse_friendlyfile_sha256,
    render_friendlyfile_sha256,
)
