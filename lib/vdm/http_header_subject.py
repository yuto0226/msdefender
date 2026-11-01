"""Callback16 ordered header recipes and two captured literal search profiles.

The formatter projection covers ASCII WCHAR CStrings or explicit external
outcomes. Literal search covers exactly two original patterns and the captured
traits fingerprint, on first-NUL subjects in the normal resource-success domain.
No HTTP role, arbitrary regex, locale discovery or post-match policy runs here.
"""

import hashlib
from dataclasses import dataclass, field

from .raw_body import UnsupportedRawBodyPattern, compile_raw_body_pattern

ENGINE_SHA256 = "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3"
TRAITS_FINGERPRINT = "9c79d87ef085bd84c48cde982d32e49d9ad10b7f4965c7f1398900911af5e5ac"
CAPTURED_FOLD256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    "406162636465666768696a6b6c6d6e6f707172737475767778797a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    "808182838485868788899a8b9c8d9e8f909192939495969798999a9b9c9d9eff"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6d7f8f9fafbfcfdfedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
)
# Exact original code pins behind the captured states/restart/literal proof.
PROFILE_CODE_SHA256 = (
    ("0x1803CB2F0", "87daf849a69b30b7c0947c8325759dd0495c4124e965fd1978ab73f2c0cfbe51"),
    ("0x1801F7820", "25d9c16a046577ea4cbb0f3fd097291d41141f10e31bd8a00b898ef9370199bc"),
    ("0x1801F7D20", "6c8a7212d17e08924f0a2d9573880f6fc91970a62f3ffc85343cdffb9f55b080"),
    ("0x1801F7400", "2e38fe54ac041be5f51379a75255623e968a6a51d55212a229c3780a7d5cf37d"),
)
_PROFILES = (
    (
        b"Expires: Wed, 21 Jan 1995 11:56:08 GMT\0",
        b"Expires: Wed, 21 Jan 1995 11:56:08 GMT",
        "f8bbcb63c7d354dcf7004b7da4afc39f2472d8d223c3c8d6b39b22e7d38697b2",
        "7588cd2b3c2a361ff8b49f3cf049b6278ef4ef49e1d57e0c4bcc53a5181d89a7",
    ),
    (
        rb"User-Agent: Mozilla/4\.0 \(compatible; MSIE 8\.0; Windows NT 6\.1 SV1; \.Net CLR 2\.0\.50727; \.NET CLR 3\.0\.04506\.648; \.NET CLR 3\.5\.21022\)"
        + b"\0",
        b"User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1 SV1; .Net CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)",
        "eff6192c72aa1ed035f01ad319354f6a35d337829d7f84719dee0362b3a3ca8f",
        "7cdf7af405c2108ac8a2011838c6589da51103aee48bc6a9d79c6a385aba2c0f",
    ),
)


class UnsupportedHttpHeaderSubject(ValueError):
    """Selected runtime input is outside the known formatter/CString domain."""


class UnsupportedHttpHeaderPattern(ValueError):
    """No local profile; this is not an original-engine compile rejection."""


def _u32(value: int) -> None:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("expected uint32")


def effective_http_header_cstring(storage: bytes) -> bytes:
    """Select readable bytes before the first NUL; never silently append NUL."""
    if not isinstance(storage, bytes):
        raise TypeError("CString storage must be bytes")
    end = storage.find(b"\0")
    if end < 0:
        raise UnsupportedHttpHeaderSubject("selected CString lacks a readable NUL")
    return storage[:end]


@dataclass(frozen=True, slots=True)
class FormatterOutcome:
    """Explicit original formatter outcome; HRESULT uses only uint32 bits.

    None status means unknown, not failure. Failure storage is deliberately not
    interpreted: a zero-initialized native out cell does not prove clearing of
    existing non-NULL output. Successful storage must contain a readable NUL.
    """

    hresult_u32: int | None
    subject_cstring_storage: bytes | None = None

    def __post_init__(self) -> None:
        if self.hresult_u32 is not None:
            _u32(self.hresult_u32)
        if self.subject_cstring_storage is not None and not isinstance(
            self.subject_cstring_storage, bytes
        ):
            raise TypeError("formatter output must be bytes or NULL")


@dataclass(frozen=True, slots=True)
class HttpHeaderPair:
    """Resolved pair+0/+8 WCHAR pointers, with optional external CRT outcome."""

    first_utf16_storage: bytes | None
    second_utf16_storage: bytes | None
    formatter_outcome: FormatterOutcome | None = None

    def __post_init__(self) -> None:
        for storage in (self.first_utf16_storage, self.second_utf16_storage):
            if storage is not None and not isinstance(storage, bytes):
                raise TypeError("WCHAR storage must be bytes or actual NULL")
        if self.formatter_outcome is not None and not isinstance(
            self.formatter_outcome, FormatterOutcome
        ):
            raise TypeError("expected an explicit FormatterOutcome")


@dataclass(frozen=True, slots=True)
class HttpHeaderGroup:
    """Logical u32 count plus physically supplied pairs; None is actual NULL."""

    logical_count: int
    pairs: tuple[HttpHeaderPair, ...] | None

    def __post_init__(self) -> None:
        _u32(self.logical_count)
        if self.pairs is not None and (
            not isinstance(self.pairs, tuple)
            or any(not isinstance(pair, HttpHeaderPair) for pair in self.pairs)
        ):
            raise TypeError("pairs must be an immutable tuple or actual NULL")


@dataclass(frozen=True, slots=True)
class HttpHeaderLists:
    """Resolved metadata+0x28 container; group roles remain unspecified."""

    group0: HttpHeaderGroup
    group1: HttpHeaderGroup

    def __post_init__(self) -> None:
        if not all(isinstance(g, HttpHeaderGroup) for g in (self.group0, self.group1)):
            raise TypeError("both original groups must be explicitly supplied")


@dataclass(frozen=True, slots=True)
class HttpHeaderQuery:
    group: int
    index: int
    policy_byte: int
    subject: bytes

    def __post_init__(self) -> None:
        if type(self.group) is not int or self.group not in (0, 1):
            raise ValueError("group must be 0 or 1")
        if type(self.policy_byte) is not int or self.policy_byte != self.group:
            raise ValueError("original policy byte must equal group 0/1")
        _u32(self.index)
        if not isinstance(self.subject, bytes) or b"\0" in self.subject:
            raise ValueError("query subject must be effective CString bytes")


def _ascii_wchar_cstring(storage: bytes | None) -> bytes:
    if storage is None:
        raise UnsupportedHttpHeaderSubject("NULL WCHAR formatting requires an outcome")
    out = bytearray()
    for offset in range(0, len(storage) - 1, 2):
        unit = int.from_bytes(storage[offset : offset + 2], "little")
        if not unit:
            return bytes(out)
        if unit > 0x7F:
            raise UnsupportedHttpHeaderSubject(
                "non-ASCII narrow CRT conversion requires an explicit outcome"
            )
        out.append(unit)
    raise UnsupportedHttpHeaderSubject("selected WCHAR storage lacks an aligned NUL")


def format_http_header_pair(pair: HttpHeaderPair) -> bytes | None:
    """Return effective bytes, or None only for a known failed HRESULT.

    Without an external outcome, project the normal ASCII success domain of
    NewSprintfA('%ls: %ls'). No UTF8 conversion, trimming or case folding occurs.
    Allocation/errors and all unmodeled CRT inputs require explicit outcomes.
    """
    if not isinstance(pair, HttpHeaderPair):
        raise TypeError("expected a resolved header pair")
    outcome = pair.formatter_outcome
    if outcome is not None:
        if outcome.hresult_u32 is None:
            raise UnsupportedHttpHeaderSubject("formatter outcome is unknown")
        if outcome.hresult_u32 & 0x80000000:
            return None
        if outcome.subject_cstring_storage is None:
            raise UnsupportedHttpHeaderSubject("successful formatter output is unknown")
        return effective_http_header_cstring(outcome.subject_cstring_storage)
    return (
        _ascii_wchar_cstring(pair.first_utf16_storage)
        + b": "
        + _ascii_wchar_cstring(pair.second_utf16_storage)
    )


def project_http_header_queries(
    lists: HttpHeaderLists | None, *, pattern_vector_present: bool
) -> tuple[HttpHeaderQuery, ...]:
    """Independent group0/policy0 then group1/policy1, never fallback.

    None container is actual NULL and skips this branch; missing/unresolved
    metadata is not represented by None. Selected missing pairs are unsupported.
    Caller/NRI, regex results, reporting and post-policy remain external.
    """
    if type(pattern_vector_present) is not bool:
        raise TypeError("pattern-vector presence must be explicitly known")
    if not pattern_vector_present or lists is None:
        return ()
    if not isinstance(lists, HttpHeaderLists):
        raise TypeError("expected resolved header lists or actual NULL")
    queries = []
    for group_index, group in enumerate((lists.group0, lists.group1)):
        if not group.logical_count:
            continue
        if group.pairs is None or len(group.pairs) < group.logical_count:
            raise UnsupportedHttpHeaderSubject(
                "selected pair array lacks readable rows"
            )
        for index in range(group.logical_count):
            subject = format_http_header_pair(group.pairs[index])
            if subject is not None:
                queries.append(
                    HttpHeaderQuery(group_index, index, group_index, subject)
                )
    return tuple(queries)


@dataclass(frozen=True, slots=True)
class HttpHeaderLiteralProfile:
    """Exact original counted pattern plus captured traits, not generic icase."""

    counted_data: bytes
    traits_fingerprint: str
    effective_pattern: bytes = field(init=False)
    literal: bytes = field(init=False)
    compiled_literal: bytes = field(init=False)
    counted_sha256: str = field(init=False)
    effective_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.counted_data, bytes):
            raise TypeError("original counted pattern must be bytes")
        if self.traits_fingerprint != TRAITS_FINGERPRINT:
            raise UnsupportedHttpHeaderPattern("uncaptured traits fingerprint")
        if hashlib.sha256(CAPTURED_FOLD256).hexdigest() != TRAITS_FINGERPRINT:
            raise UnsupportedHttpHeaderPattern("captured fold-table integrity failure")
        for raw, witness, raw_sha, effective_sha in _PROFILES:
            if self.counted_data != raw:
                continue
            effective = raw[:-1]
            try:
                ast = compile_raw_body_pattern(effective)
            except UnsupportedRawBodyPattern as exc:
                raise UnsupportedHttpHeaderPattern(
                    "frozen literal syntax changed"
                ) from exc
            if len(ast.branches) != 1:
                raise UnsupportedHttpHeaderPattern("expected one fixed literal branch")
            branch = ast.branches[0]
            if (
                branch.start_anchor
                or branch.end_anchor
                or any(
                    t.value is None or t.minimum != 1 or t.maximum != 1
                    for t in branch.tokens
                )
            ):
                raise UnsupportedHttpHeaderPattern(
                    "expected fixed bytes without anchors"
                )
            literal = bytes(t.value for t in branch.tokens)
            if (
                literal != witness
                or hashlib.sha256(raw).hexdigest() != raw_sha
                or hashlib.sha256(effective).hexdigest() != effective_sha
            ):
                raise UnsupportedHttpHeaderPattern(
                    "frozen literal profile integrity failure"
                )
            for name, value in (
                ("effective_pattern", effective),
                ("literal", literal),
                ("compiled_literal", literal.translate(CAPTURED_FOLD256)),
                ("counted_sha256", raw_sha),
                ("effective_sha256", effective_sha),
            ):
                object.__setattr__(self, name, value)
            return
        raise UnsupportedHttpHeaderPattern(
            "no portable profile for this exact pattern; original Boost compile remains external"
        )


def compile_http_header_literal(
    counted_data: bytes, *, traits_fingerprint: str
) -> HttpHeaderLiteralProfile:
    """Select one of the two captured original patterns; never compile Boost."""
    return HttpHeaderLiteralProfile(counted_data, traits_fingerprint)


def search_http_header_cstring(
    profile: HttpHeaderLiteralProfile, subject_cstring_storage: bytes
) -> bool:
    """Normal-resource Boolean search on identical first-NUL subject bytes.

    Captured opcode0/2/6 and restart0 establish substring classes for these two
    profiles. Resource/exception false, all other traits and post-policy are not
    modeled. In particular, callback17 has no subject contract here.
    """
    if not isinstance(profile, HttpHeaderLiteralProfile):
        raise TypeError("expected an exact captured literal profile")
    subject = effective_http_header_cstring(subject_cstring_storage)
    return profile.compiled_literal in subject.translate(CAPTURED_FOLD256)


def http_header_literal_yara_rhs(profile: HttpHeaderLiteralProfile) -> str:
    """Exact hex RHS only for the same projected effective subject.

    Caller must first apply CString selection. This fragment is not a rule on
    whole files, raw HTTP, arbitrary materialized storage or network policy.
    """
    if not isinstance(profile, HttpHeaderLiteralProfile):
        raise TypeError("expected an exact captured literal profile")
    atoms = []
    for target in profile.compiled_literal:
        values = [i for i, byte in enumerate(CAPTURED_FOLD256) if byte == target]
        if not values or 0 in values:
            raise UnsupportedHttpHeaderPattern(
                "literal class is outside this RHS profile"
            )
        atoms.append(
            f"{values[0]:02X}"
            if len(values) == 1
            else "( " + " | ".join(f"{v:02X}" for v in values) + " )"
        )
    return "{ " + " ".join(atoms) + " }"
