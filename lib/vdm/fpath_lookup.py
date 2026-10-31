"""Pinned original-image CSIDL lookup, preserving the engine's binary search.

The original keys are not sorted. Membership or a sorted copy is not equivalent
to this helper. Normal PE relocation preserves these read-only, nonrelocated key
bytes; this profile does not execute engine initialization or path expansion.
"""

from types import MappingProxyType
from typing import Final

CSIDL_INDEX_MISS: Final = 0x7FFFFFFF
ORIGINAL_CSIDL_LOOKUP_PROFILE: Final = MappingProxyType(
    {
        "id": "mpengine-1.443.903.0.original-readonly-csidl-keys.v1",
        "table_va": 0x180DB98D0,
        "row_count": 49,
        "row_stride": 0x28,
        "key_offset": 0x20,
        "key_width": 2,
        "key_comparison": "unsigned_little_endian_u16",
        "table_sha256": "15a4871ff4c533362b2fca9d761fc01956e6a69eb1f05276ddec2e27629f75b0",
        "binary_sha256": "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3",
        "search": "original_crt_binary_search_even_lower_midpoint",
        "keys_nondecreasing": False,
        "normal_pe_key_relocation_overlap_count": 0,
        "original_section_readable": True,
        "original_section_writable": False,
        "initialized_engine_executed": False,
    }
)
_ORIGINAL_CSIDL_KEYS: Final = (
    2,
    5,
    6,
    7,
    8,
    9,
    11,
    13,
    14,
    16,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    31,
    32,
    33,
    34,
    35,
    35,
    36,
    37,
    38,
    39,
    40,
    45,
    46,
    47,
    48,
    53,
    54,
    55,
    59,
    56,
    5,
    42,
    43,
    65530,
    65531,
    65532,
    65533,
    65534,
    65535,
)


def lookup_original_csidl_index(selector: int) -> int:
    """Return the pinned key-state helper index or ``CSIDL_INDEX_MISS``.

    Only strict uint16 integers are accepted. The returned index is a table row,
    not an expanded path, record acceptance, or Defender verdict. Callers must
    retain the profile's original/read-only key-state assumption.
    """
    if type(selector) is not int:
        raise TypeError("CSIDL selector must be an integer, excluding bool")
    if not 0 <= selector <= 0xFFFF:
        raise ValueError("CSIDL selector must fit uint16")
    low, high, count = 0, len(_ORIGINAL_CSIDL_KEYS) - 1, len(_ORIGINAL_CSIDL_KEYS)
    while low <= high:
        half = count >> 1
        if not half:
            if count and selector == _ORIGINAL_CSIDL_KEYS[low]:
                return low
            return CSIDL_INDEX_MISS
        count = half if count & 1 else half - 1
        middle = low + count
        key = _ORIGINAL_CSIDL_KEYS[middle]
        if selector == key:
            return middle
        if selector < key:
            high = middle - 1
        else:
            low, count = middle + 1, half
    return CSIDL_INDEX_MISS
