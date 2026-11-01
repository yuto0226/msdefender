"""Bounded callback-20 byte language and raw metadata subject projection.

This is not a general Boost regex engine, certificate parser or network policy.
The fixed-width case-sensitive subset is independent of the runtime w32 locale.
"""

from dataclasses import dataclass


class UnsupportedRawSslPattern(ValueError):
    """The effective Boost pattern is outside the fixed-width byte subset."""


class UnsupportedRawSslSubject(ValueError):
    """Physical input cannot supply the original selected runtime range."""


@dataclass(frozen=True, slots=True)
class RawSslByteAtom:
    value: int
    negated: bool = False

    def __post_init__(self) -> None:
        if type(self.value) is not int or not 0 <= self.value <= 255:
            raise ValueError("atom value must be uint8")
        if type(self.negated) is not bool:
            raise TypeError("negated must be bool")


@dataclass(frozen=True, slots=True)
class RawSslBytePattern:
    """Immutable nonempty fixed-width atoms, with no nullable or regex state."""

    atoms: tuple[RawSslByteAtom, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.atoms, tuple) or not self.atoms:
            raise ValueError("a nonempty immutable atom tuple is required")
        if any(not isinstance(a, RawSslByteAtom) for a in self.atoms):
            raise TypeError("expected byte atoms")


def compile_raw_ssl_byte_pattern(effective_pattern: bytes) -> RawSslBytePattern:
    """Project only ASCII \\xHH, literal H and [^\\xHH] tokens.

    Input is the effective bytes before the constructor's first NUL. This does
    not validate arbitrary Boost grammar or invoke the original constructor.
    """
    if not isinstance(effective_pattern, bytes):
        raise TypeError("effective pattern must be bytes")
    atoms = []
    offset = 0
    hexdigits = b"0123456789abcdefABCDEF"
    while offset < len(effective_pattern):
        negated = effective_pattern[offset : offset + 2] == b"[^"
        begin = offset + 2 if negated else offset
        token = effective_pattern[begin : begin + 4]
        if (
            len(token) == 4
            and token[:2] == b"\\x"
            and all(c in hexdigits for c in token[2:])
        ):
            end = begin + 4
            if negated:
                if effective_pattern[end : end + 1] != b"]":
                    raise UnsupportedRawSslPattern("unsupported negated byte class")
                end += 1
            atoms.append(
                RawSslByteAtom(bytes.fromhex(token[2:].decode("ascii"))[0], negated)
            )
            offset = end
        elif not negated and effective_pattern[offset : offset + 1] == b"H":
            atoms.append(RawSslByteAtom(0x48))
            offset += 1
        else:
            raise UnsupportedRawSslPattern("outside the fixed byte-token language")
    if not atoms:
        raise UnsupportedRawSslPattern("empty/nullable pattern is outside the subset")
    return RawSslBytePattern(tuple(atoms))


def search_raw_ssl_bytes(pattern: RawSslBytePattern, subject: bytes) -> bool:
    """Boolean search on exactly these bytes, including NUL; no post-policy."""
    if not isinstance(pattern, RawSslBytePattern) or not isinstance(subject, bytes):
        raise TypeError("expected a projected pattern and exact subject bytes")
    if not any(a.negated for a in pattern.atoms):
        return bytes(a.value for a in pattern.atoms) in subject
    width = len(pattern.atoms)
    return any(
        all(
            (subject[start + i] != atom.value)
            if atom.negated
            else (subject[start + i] == atom.value)
            for i, atom in enumerate(pattern.atoms)
        )
        for start in range(len(subject) - width + 1)
    )


def raw_ssl_yara_rhs(pattern: RawSslBytePattern) -> str:
    """Hex RHS for the same explicit span; no YARA runtime is imported."""
    if not isinstance(pattern, RawSslBytePattern):
        raise TypeError("expected a projected byte pattern")
    return (
        "{ "
        + " ".join(("~" if a.negated else "") + f"{a.value:02X}" for a in pattern.atoms)
        + " }"
    )


@dataclass(frozen=True, slots=True)
class RawSslMetadataView:
    """Resolved metadata+0x40 view: buffer pointer+8 and logical u32 size+4.

    None buffer means an actual NULL pointer, not unavailable physical bytes.
    This view is not a TLS decoder or a complete NetworkHipsMatch context.
    """

    buffer: bytes | None
    logical_size: int

    def __post_init__(self) -> None:
        if self.buffer is not None and not isinstance(self.buffer, bytes):
            raise TypeError("physical buffer must be bytes or NULL")
        if (
            type(self.logical_size) is not int
            or not 0 <= self.logical_size <= 0xFFFFFFFF
        ):
            raise ValueError("logical size must be uint32")


@dataclass(frozen=True, slots=True)
class RawSslSubject:
    """Recipe-local gate/result, not global-pattern or policy eligibility."""

    subject: bytes | None
    parser_span: bytes | None
    declared_length: int | None
    reason: str

    @property
    def subject_available(self) -> bool:
        return self.subject is not None


def project_raw_ssl_subject(view: RawSslMetadataView | None) -> RawSslSubject:
    """Apply original view gates; raw search covers buffer[6:logical_size].

    BE24 buffer[3:6] only gates bounds and selects the later parser span. Zero
    declared length is allowed. Prefix bytes have no assigned interpretation.
    Unknown mapping/resources, upstream metadata and pattern/policy are external.
    """
    if view is None:
        return RawSslSubject(None, None, None, "null_view")
    if not isinstance(view, RawSslMetadataView):
        raise TypeError("expected a resolved runtime metadata view or NULL")
    data, size = view.buffer, view.logical_size
    if data is None:
        return RawSslSubject(None, None, None, "null_buffer")
    if size < 6:
        return RawSslSubject(None, None, None, "logical_size_below_six")
    if len(data) < 6:
        raise UnsupportedRawSslSubject("selected header is not physically readable")
    declared = int.from_bytes(data[3:6], "big")
    if declared > size - 6:
        return RawSslSubject(None, None, declared, "declared_length_exceeds_remaining")
    if len(data) < size:
        raise UnsupportedRawSslSubject(
            "selected remaining span is not physically readable"
        )
    return RawSslSubject(
        data[6:size], data[6 : 6 + declared], declared, "raw_remaining_span"
    )
