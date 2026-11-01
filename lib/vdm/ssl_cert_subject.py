"""Local SSL-certificate subject recipes from parsed runtime views.

No DER/ASN.1 parser, registry, regex engine or NRI policy runs here. DN output
uses the bounded ASCII success projection of the original narrow CRT format.
Unavailable subject bytes differ from unsupported runtime input.
"""

from dataclasses import dataclass
from typing import Literal


class UnsupportedSslCertSubject(ValueError):
    """The supplied runtime view is outside the modeled success domain."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"expected uint{bits}")


@dataclass(frozen=True, slots=True)
class SslDnStringRow:
    """Resolved view of one runtime 24-byte DN row, not encoded certificate data.

    string_type is row+0 u32; value_utf16_storage resolves row+16's WCHAR pointer.
    None is a real NULL pointer. Non-NULL storage must physically contain an
    aligned terminating WCHAR when selected; bytes after that NUL are not read.
    Unknown or shadowed rows do not require decodable value storage.
    """

    string_type: int
    value_utf16_storage: bytes | None

    def __post_init__(self) -> None:
        _uint(self.string_type, 32)
        if self.value_utf16_storage is not None and not isinstance(
            self.value_utf16_storage, bytes
        ):
            raise TypeError("value storage must be bytes or NULL")


@dataclass(frozen=True, slots=True)
class SslValiditySnapshot:
    """Raw parsed-certificate time fields consumed by Matchx509Validity.

    valid_from_words: eight u16 SYSTEMTIME words at certificate+88.
    valid_to_words: eight u16 SYSTEMTIME words at certificate+104.
    offset_dwords: four raw u32 values at +120/+124/+128/+132, in that order.
    No date or signed-timezone interpretation is imposed on these raw fields.
    """

    valid_from_words: tuple[int, ...]
    valid_to_words: tuple[int, ...]
    offset_dwords: tuple[int, ...]

    def __post_init__(self) -> None:
        for words, length, bits in (
            (self.valid_from_words, 8, 16),
            (self.valid_to_words, 8, 16),
            (self.offset_dwords, 4, 32),
        ):
            if not isinstance(words, tuple) or len(words) != length:
                raise ValueError(f"expected an immutable {length}-word runtime view")
            for value in words:
                _uint(value, bits)


@dataclass(frozen=True, slots=True)
class SslCertSubject:
    """Recipe-local subject availability, not engine query eligibility or match."""

    kind: str
    subject: bytes | None
    reason: str

    @property
    def subject_available(self) -> bool:
        """Other global-vector, formatting/resource and policy gates are external."""
        return self.subject is not None


def _ascii_wchar_cstring(storage: bytes) -> bytes:
    output = bytearray()
    for offset in range(0, len(storage) - 1, 2):
        unit = int.from_bytes(storage[offset : offset + 2], "little")
        if unit == 0:
            return bytes(output)
        if unit > 0x7F:
            raise UnsupportedSslCertSubject(
                "selected DN value requires an unmodeled narrow CRT conversion"
            )
        output.append(unit)
    raise UnsupportedSslCertSubject(
        "selected WCHAR storage lacks a readable terminator"
    )


def build_ssl_dn_subject(
    label: Literal["Subject", "Issuer"], rows: tuple[SslDnStringRow, ...]
) -> SslCertSubject:
    """Build the ASCII DN recipe using first matching type, including NULL.

    Preserve empty values and CString boundaries; ignore unknown/shadowed rows.
    An absent subject means no selected fields, not a false regex result. The
    original function's NRI field checks and post-match policy are not evaluated.
    """
    if label not in ("Subject", "Issuer"):
        raise UnsupportedSslCertSubject("label is outside the two analyzed callers")
    if not isinstance(rows, tuple) or any(
        not isinstance(r, SslDnStringRow) for r in rows
    ):
        raise TypeError("rows must be an immutable tuple of parsed runtime DN rows")
    parts: list[bytes] = []
    for string_type, short_label in (
        (12, b"EMAIL"),
        (5, b"CN"),
        (4, b"OU"),
        (3, b"O"),
        (2, b"L"),
        (1, b"ST"),
        (0, b"C"),
    ):
        row = next((r for r in rows if r.string_type == string_type), None)
        if row is None or row.value_utf16_storage is None:
            continue
        content = _ascii_wchar_cstring(row.value_utf16_storage)
        parts.append(short_label + b"=" + content)
    if not parts:
        return SslCertSubject(label, None, "no_selected_dn_fields")
    return SslCertSubject(
        label, label.encode("ascii") + b": " + b", ".join(parts), "ascii_dn_subject"
    )


def build_ssl_validity_subject(view: SslValiditySnapshot) -> SslCertSubject:
    """Format raw unsigned fields, without date validation or current-time logic.

    A zero first WORD in either time view supplies no recipe-local subject.
    The original global-pattern-vector gate and query policy remain external.
    """
    start, end = view.valid_from_words, view.valid_to_words
    if start[0] == 0 or end[0] == 0:
        return SslCertSubject("Validity", None, "zero_year_word")

    def part(words: tuple[int, ...], offset1: int, offset2: int) -> str:
        return (
            f"{words[0]:04d}-{words[1]:02d}-{words[3]:02d} "
            f"{words[4]:02d}:{words[5]:02d}:{words[6]:02d} "
            f"(UTC + {offset1:02d}:{offset2:02d})"
        )

    offsets = view.offset_dwords
    text = f"ValidFrom: {part(start, offsets[0], offsets[1])} ValidTo: {part(end, offsets[2], offsets[3])}"
    return SslCertSubject("Validity", text.encode("ascii"), "unsigned_validity_subject")
