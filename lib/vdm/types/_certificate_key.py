"""Shared, lossless interpretation of certificate key data."""

from dataclasses import dataclass
from typing import Literal

_PREFIX_TYPES = (
    ("HASH:", 1),
    ("BADHASH:", 4),
    ("BY:", 2),
    ("TO:", 3),
    ("TEAMID:", 5),
)


@dataclass(frozen=True, slots=True)
class CertificateKey:
    mode: Literal["binary", "string"]
    key_type: int
    prefix: str | None
    prefix_raw: bytes
    material_raw: bytes
    text: str | None
    text_raw: bytes
    terminator_raw: bytes
    trailing_raw: bytes
    decode_error: str | None


def parse_certificate_key(key_data: bytes) -> CertificateKey:
    """Interpret a validated, non-empty key while retaining every byte."""
    mode: Literal["binary", "string"] = "binary" if key_data[0] < 0x20 else "string"
    key_type = key_data[0] if mode == "binary" else 3
    prefix = None
    prefix_raw = b""
    material_raw = key_data[1:] if mode == "binary" else key_data
    text_raw = b""
    terminator_raw = b""
    trailing_raw = b""
    text = None
    decode_error = None

    if mode == "string":
        for label, candidate_type in _PREFIX_TYPES:
            encoded = label.encode("utf-16le")
            if key_data[: len(encoded)].upper() == encoded:
                prefix = label[:-1]
                prefix_raw = key_data[: len(encoded)]
                material_raw = key_data[len(encoded) :]
                key_type = candidate_type
                break

        # The wide GetKey overload receives the material after a recognized
        # prefix, not the complete key descriptor.
        text_raw = material_raw
        for offset in range(0, len(material_raw) - 1, 2):
            if material_raw[offset : offset + 2] == b"\0\0":
                text_raw = material_raw[:offset]
                terminator_raw = material_raw[offset : offset + 2]
                trailing_raw = material_raw[offset + 2 :]
                break
        try:
            text = text_raw.decode("utf-16le")
        except UnicodeDecodeError as exc:
            decode_error = str(exc)

    return CertificateKey(
        mode=mode,
        key_type=key_type,
        prefix=prefix,
        prefix_raw=prefix_raw,
        material_raw=material_raw,
        text=text,
        text_raw=text_raw,
        terminator_raw=terminator_raw,
        trailing_raw=trailing_raw,
        decode_error=decode_error,
    )
