"""REGKEY query projection and a local, prebound registry-state predicate.

This models successful CP_UTF8 conversion of valid UTF-8 and the original
ASCII-only WCHAR comparator. Resolver outputs and post-offline-patch bytes are
external observations; path equality is computed locally. Buffers contain
physical readable bytes, not padded declared sizes.
"""

from dataclasses import dataclass

from .regkey_paths import (
    RegKeyExpansionSnapshot,
    RegKeyPathComparison,
    project_regkey_expansion,
)
from .types.regkey import REGKEY_HIVES, REGKEY_PREFIXES, RegKeyPayload, parse_regkey


class UnsupportedRegKeyQuery(ValueError):
    """The supplied input is outside the successful conversion profile."""


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"expected uint{bits}")


def _wide(raw: bytes) -> bytes:
    try:
        return raw.split(b"\0", 1)[0].decode("utf-8").encode("utf-16le")
    except UnicodeError as exc:
        raise UnsupportedRegKeyQuery("valid UTF-8 success profile required") from exc


def _cstring(raw: bytes) -> bytes | None:
    for offset in range(0, len(raw) - 1, 2):
        if raw[offset : offset + 2] == b"\0\0":
            return raw[:offset]
    return None


@dataclass(frozen=True, slots=True)
class RegKeyAsepBinding:
    """Actual caller-resolved RealRK and caller value-name CString content.

    resolved_key_utf16 is NUL-free UTF-16 code-unit content (no terminator).
    None value_name_utf8 means a NULL pointer; b'' means the default value.
    This binding does not implement LUM resolution or ASEP candidate lookup.
    """

    resolved_key_utf16: bytes
    value_name_utf8: bytes | None

    def __post_init__(self) -> None:
        if len(self.resolved_key_utf16) % 2 or any(
            self.resolved_key_utf16[i : i + 2] == b"\0\0"
            for i in range(0, len(self.resolved_key_utf16), 2)
        ):
            raise ValueError("resolved key must be NUL-free WCHAR content")
        if self.value_name_utf8 is not None and b"\0" in self.value_name_utf8:
            raise ValueError("caller value name must be CString content")


@dataclass(frozen=True, slots=True)
class RegKeyQueryRecipe:
    """UTF-16 fields exclude terminators; pointer NULL remains None."""

    kind: str
    hive: str | None
    key_utf16: bytes | None
    value_name_utf16: bytes | None
    expected_utf16: bytes | None
    binding_required: bool = False


def project_regkey_query(
    record: RegKeyPayload, *, asep_binding: RegKeyAsepBinding | None = None
) -> RegKeyQueryRecipe:
    """Reparse raw wire bytes; general keys are logical, ASEP keys caller-bound.

    A general recipe still requires the real registry/LUM binding before its
    supplied query snapshot is authoritative. Ignored selectors issue no query.
    """
    row = parse_regkey(record.raw)
    if not 1 <= row.key_type <= 4:
        return RegKeyQueryRecipe("ignored", None, None, None, None)
    path = row.key_path_raw.split(b"\0", 1)[0]
    prefix = next(
        (
            p.encode("ascii")
            for p in REGKEY_PREFIXES
            if path.lower().startswith(p.encode("ascii"))
        ),
        b"",
    )
    stored = path[len(prefix) :]
    key, separator, name = stored.partition(b"\\\\")
    expected = None if not row.value_raw else _wide(row.value_raw)
    hive = REGKEY_HIVES[row.key_type - 1]
    if not separator and row.value_raw:
        if asep_binding is None:
            return RegKeyQueryRecipe("asep", hive, None, None, expected, True)
        return RegKeyQueryRecipe(
            "asep",
            hive,
            asep_binding.resolved_key_utf16,
            None
            if asep_binding.value_name_utf8 is None
            else _wide(asep_binding.value_name_utf8),
            expected,
        )
    full_key = hive.encode("ascii") + b"\\" + prefix + key
    return RegKeyQueryRecipe(
        "general", hive, _wide(full_key), _wide(name) if separator else None, expected
    )


@dataclass(frozen=True, slots=True)
class RegKeyValueSnapshot:
    """Runtime type, GetData size_t and independently readable buffer bytes."""

    registry_type: int
    declared_size: int
    readable_data: bytes | None

    def __post_init__(self) -> None:
        _uint(self.registry_type, 32)
        _uint(self.declared_size, 64)


@dataclass(frozen=True, slots=True)
class RegKeyQuerySnapshot:
    """Win32 OpenSubKey/GetValue statuses for this actual prebound query."""

    key_open_status: int | None
    value_query_status: int | None = None
    value: RegKeyValueSnapshot | None = None

    def __post_init__(self) -> None:
        for status in (self.key_open_status, self.value_query_status):
            if status is not None:
                _uint(status, 32)


@dataclass(frozen=True, slots=True)
class RegKeyMatch:
    recipe: RegKeyQueryRecipe
    record_local_match: bool | None
    reason: str
    path_comparison: RegKeyPathComparison | None = None


def _ascii_wide_lower(raw: bytes) -> tuple[int, ...]:
    units = tuple(
        int.from_bytes(raw[i : i + 2], "little") for i in range(0, len(raw), 2)
    )
    return tuple(unit + 32 if 65 <= unit <= 90 else unit for unit in units)


def evaluate_regkey(
    record: RegKeyPayload,
    query_snapshot: RegKeyQuerySnapshot,
    *,
    asep_binding: RegKeyAsepBinding | None = None,
    expansion_snapshot: RegKeyExpansionSnapshot | None = None,
) -> RegKeyMatch:
    """Evaluate only ResutilsRegKeyInHive's local predicate, lazily.

    Direct string mismatch requires concrete, invocation-bound postpatch and
    resolver observations. None means unknown. No registry or path I/O occurs.
    """
    recipe = project_regkey_query(record, asep_binding=asep_binding)

    def result(value: bool | None, reason: str) -> RegKeyMatch:
        return RegKeyMatch(recipe, value, reason)

    if recipe.kind == "ignored":
        return result(None, "receiver_ignored")
    if recipe.binding_required:
        return result(None, "asep_caller_binding_required")
    if query_snapshot.key_open_status is None:
        return result(None, "key_open_status_unknown")
    if query_snapshot.key_open_status != 0:
        return result(False, "key_open_failed")
    if recipe.value_name_utf16 is None:
        return result(True, "key_exists")
    if query_snapshot.value_query_status is None:
        return result(None, "value_query_status_unknown")
    if query_snapshot.value_query_status != 0:
        return result(False, "value_query_failed")
    expected = recipe.expected_utf16
    if expected is None:
        return result(True, "value_exists")
    value = query_snapshot.value
    if value is None:
        return result(None, "value_data_unknown")
    data = value.readable_data
    kind = value.registry_type
    if kind in (1, 2):
        content = None if data is None else _cstring(data)
        if content is None:
            return result(None, "readable_wchar_terminator_required")
        if _ascii_wide_lower(content) == _ascii_wide_lower(expected):
            return result(True, "direct_string_equal")
        comparison = project_regkey_expansion(
            record.raw, data, expected, kind == 2, expansion_snapshot
        )
        return RegKeyMatch(
            recipe, comparison.record_local_match, comparison.reason, comparison
        )
    if kind == 3:
        size = value.declared_size & 0xFFFFFFFF
        if size not in (len(expected), len(expected) + 2):
            return result(False, "binary_size_mismatch")
        if size and (data is None or len(data) < size):
            return result(None, "readable_binary_bytes_required")
        return result(
            (data or b"")[:size] == (expected + b"\0\0")[:size], "binary_compare"
        )
    if kind in (4, 5):
        needed = 4 if kind == 4 else 1
        if data is None or len(data) < needed:
            return result(None, "readable_numeric_bytes_required")
        number = int.from_bytes(data[:4], "little") if kind == 4 else data[0] << 24
        return result(
            str(number).encode("utf-16le") == expected, "unsigned_decimal_compare"
        )
    return result(False, "unsupported_runtime_type")
