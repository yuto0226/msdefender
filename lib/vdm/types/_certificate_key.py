"""Shared, lossless interpretation of certificate key data."""

import hashlib
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


class UnsupportedCertificateKey(ValueError):
    """The raw key is outside the verified successful GetKey projection."""


@dataclass(frozen=True, slots=True)
class CertificateKeyNormalization:
    normalized_key: bytes
    key_type: int
    operation: str


def normalize_binary_certificate_key(key_type: int, material: bytes) -> bytes:
    """Original binary GetKey value; type is a raw byte, not a policy enum."""
    if type(key_type) is not int or not 0 <= key_type <= 255:
        raise ValueError("key_type must be uint8")
    if not isinstance(material, bytes):
        raise TypeError("material must be bytes")
    if key_type in {1, 4} and len(material) == 20:
        return bytes(((material[0] + key_type) & 255,)) + material[1:]
    return hashlib.sha1(bytes((key_type,)) + material).digest()


def normalize_certificate_key(key_data: bytes) -> CertificateKeyNormalization:
    """Project successful GetKey under the C-locale prefix/CP_UTF8 flags0 profile.

    Explicit aligned wide NUL is required. Windows flags0 replaces unpaired
    UTF16 surrogates with U+FFFD; this is conversion success, not raw fallback.
    API/allocation failure and invalid-hex C++ catch are outside this projection.
    The input is the receiver's entire bounded key span, including its type or
    prefix; bytes after the first wide NUL do not enter the digest.
    """
    if not isinstance(key_data, bytes):
        raise TypeError("key_data must be immutable bytes")
    if not 2 <= len(key_data) <= 0xFFFF:
        raise UnsupportedCertificateKey(
            "receiver key span must fit u16 and contain at least two bytes"
        )
    key = parse_certificate_key(key_data)
    if key.mode == "binary":
        return CertificateKeyNormalization(
            normalize_binary_certificate_key(key.key_type, key.material_raw),
            key.key_type,
            "copy_digest_then_add_type_to_first_byte"
            if key.key_type in {1, 4} and len(key.material_raw) == 20
            else "sha1(type_byte || binary_material)",
        )
    if not key.terminator_raw:
        raise UnsupportedCertificateKey("explicit aligned UTF16 NUL required")
    material_raw = key.text_raw[len(key.prefix_raw) :]
    if key.key_type in {1, 4}:
        # Validate every code unit; bytes.fromhex alone would accept whitespace.
        text = material_raw.decode("utf-16le", errors="surrogatepass")
        if len(text) % 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
            raise UnsupportedCertificateKey("invalid hex C++ catch is not modeled")
        material = bytes.fromhex(text)
        operation = "GetKey_wide_hex"
    else:
        material = material_raw.decode("utf-16le", errors="replace").encode("utf-8")
        operation = "GetKey_wide_CP_UTF8_flags0_success"
    return CertificateKeyNormalization(
        normalize_binary_certificate_key(key.key_type, material),
        key.key_type,
        operation,
    )


def certificate_key_profile(key_data: bytes) -> dict[str, object]:
    """Serializable recipe/status for the same raw-key callable in both families."""
    result: dict[str, object] = {
        "callable": "lib.vdm.types._certificate_key.normalize_certificate_key",
        "result_type": "lib.vdm.types._certificate_key.CertificateKeyNormalization",
        "unsupported_error": "lib.vdm.types._certificate_key.UnsupportedCertificateKey",
        "profile": "C_locale_prefix_CP_UTF8_flags0_successful_projection",
        "status": "not_modeled",
        "normalized_key_hex": None,
        "operation": None,
        "unsupported_reason": None,
        "unknown_boundary": "API/allocation failure fallback, invalid-hex C++ catch, X509 field selection, lookup and final trust policy",
    }
    try:
        normalized = normalize_certificate_key(key_data)
    except UnsupportedCertificateKey as exc:
        result["unsupported_reason"] = str(exc)
    else:
        result.update(
            status="normalized",
            normalized_key_hex=normalized.normalized_key.hex(),
            operation=normalized.operation,
        )
    return result


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

        text_raw = key_data
        for offset in range(0, len(key_data) - 1, 2):
            if key_data[offset : offset + 2] == b"\0\0":
                text_raw = key_data[:offset]
                terminator_raw = key_data[offset : offset + 2]
                trailing_raw = key_data[offset + 2 :]
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
