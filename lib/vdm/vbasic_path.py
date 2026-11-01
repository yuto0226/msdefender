"""VB6 parsed-field UTF8 source recipe for callback1's true-query branch.

This is not a PE/VB loader, regex engine or low-byte recovery implementation.
The original source mapping, parser/version gates and runtime resources remain
external; conversion projects CP_UTF8/flags0 over resolved WCHAR storage.
"""

from dataclasses import dataclass


class UnsupportedVbasicPathSource(ValueError):
    """Required resolved parser-field storage is absent or unreadable."""


@dataclass(frozen=True, slots=True)
class VbasicPathField:
    """Resolved parser+0xB0 field storage, not arbitrary path text.

    Load_VBasicData copies the522B mapped VBProjectInfo+0x2A field here. The
    worker only reads its first520B, so the last2B and any extra storage are
    irrelevant to this projection. Mapping/version/parser gates are not run.
    """

    storage: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.storage, bytes):
            raise TypeError("resolved parser-field storage must be bytes")


@dataclass(frozen=True, slots=True)
class VbasicPathSource:
    """Local conversion/query preparation, not engine query-policy eligibility.

    api_return_count includes NUL on success. api_error_code only models the
    proven insufficient-capacity outcome, not thread LastError on success.
    worker_cstring reflects the worker's failure[0]=0/success[259]=0 writes;
    unobserved output-buffer bytes are not manufactured.
    """

    forced_wide_cstring: bytes
    api_return_count: int
    api_error_code: int | None
    worker_cstring: bytes
    regex_subject: bytes | None
    caller_hash_cstring: bytes | None
    reason: str

    @property
    def conversion_succeeded(self) -> bool:
        return self.api_return_count > 0

    @property
    def subject_available(self) -> bool:
        return self.regex_subject is not None

    @property
    def scan_filepath_length(self) -> int | None:
        """Length including NUL, only when the original true call is prepared."""
        return (
            None if self.caller_hash_cstring is None else len(self.caller_hash_cstring)
        )


def project_vbasic_path_source(field: VbasicPathField | None) -> VbasicPathSource:
    """Project original WCHAR260/forced259NUL/UTF8 output260-byte success domain.

    UTF16LE invalid surrogate sequences use replacement, as CP_UTF8 flags0 in
    the pinned Win32 oracle. No Unicode normalization or casefold occurs.
    Capacity failure makes the worker CString empty. Success on an empty
    source is distinct and also supplies no regex/hash call. The separate
    low-byte recovery false branch never becomes a second regex subject.
    """
    if not isinstance(field, VbasicPathField):
        raise UnsupportedVbasicPathSource("missing typed resolved parser path field")
    if len(field.storage) < 520:
        raise UnsupportedVbasicPathSource(
            "worker requires520 readable bytes at parser+0xB0"
        )
    wide = field.storage[:518] + b"\0\0"
    first_nul = next(
        offset for offset in range(0, 520, 2) if wide[offset : offset + 2] == b"\0\0"
    )
    wide_cstring = wide[: first_nul + 2]
    utf8 = wide[:first_nul].decode("utf-16le", errors="replace").encode("utf-8")
    required = len(utf8) + 1
    if required > 260:
        return VbasicPathSource(
            wide_cstring, 0, 122, b"\0", None, None, "insufficient_utf8_output_capacity"
        )
    cstring = utf8 + b"\0"
    # Success's forced output[259]=0 is either this terminator or outside the
    # CString. No normalization, heap retry or output truncation is performed.
    if not utf8:
        return VbasicPathSource(
            wide_cstring,
            required,
            None,
            cstring,
            None,
            None,
            "conversion_succeeded_empty_query_skipped",
        )
    return VbasicPathSource(
        wide_cstring,
        required,
        None,
        cstring,
        utf8,
        cstring,
        "conversion_succeeded_nonempty_true_query",
    )
