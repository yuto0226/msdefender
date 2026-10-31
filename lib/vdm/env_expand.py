"""Original environment-template text algorithm under explicit runtime inputs.

This profile assumes the pinned CRT locale-changed flag is zero and output
allocation/append operations succeed. It does not read process environment,
model allocation failures, initialize engine state, or virtualize paths.
"""

from collections.abc import Callable, Sequence
from types import MappingProxyType
from typing import Final

ORIGINAL_ENV_EXPANSION_PROFILE: Final = MappingProxyType(
    {
        "name": "mpengine.original_env.raw_c_locale_u16.v1",
        "function": "ExpandEnvrPaths",
        "function_va": 0x1800C6C10,
        "input": "UTF-16LE code units with surrogatepass; first NUL terminates",
        "entries": "ordered profile then system; first finite-prefix match",
        "locale_precondition": "__acrt_locale_changed_data == 0",
        "comparison": "fold only UTF-16 code units 0x41..0x5a by adding 0x20",
        "resource_precondition": "output allocation and append succeed",
        "api_backend": "caller-supplied CallExpandAPI net text-or-NULL result",
        "outside_profile": (
            "locale_changed_nonzero",
            "allocation_and_strsafe_resource_failures",
            "runtime_environment_list_binding",
            "real_Win32_API_environment",
            "VirtualizeSimplePath_and_WOW",
        ),
    }
)


class MissingEnvironmentApiBackend(RuntimeError):
    """A missing provider value requires an API backend that was not supplied."""


def _u16_cstr(text: str) -> tuple[int, ...]:
    raw = text.encode("utf-16le", errors="surrogatepass")
    units = tuple(raw[i] | raw[i + 1] << 8 for i in range(0, len(raw), 2))
    return units[: units.index(0)] if 0 in units else units


def _text(units: Sequence[int]) -> str:
    return b"".join(unit.to_bytes(2, "little") for unit in units).decode(
        "utf-16le", errors="surrogatepass"
    )


def _fold(unit: int) -> int:
    return unit + 0x20 if 0x41 <= unit <= 0x5A else unit


def _find_value(
    entries: Sequence[tuple[str, str | None]], token: tuple[int, ...]
) -> tuple[int, ...] | None:
    for key, value in entries:
        key_units = _u16_cstr(key)
        if len(key_units) >= len(token) and all(
            _fold(a) == _fold(b) for a, b in zip(token, key_units)
        ):
            # The first matching NULL value ends this list's search too.
            return None if value is None else _u16_cstr(value)
    return None


def expand_original_env_template(
    input: str | None,
    profile_entries: Sequence[tuple[str, str | None]],
    system_entries: Sequence[tuple[str, str | None]],
    *,
    allow_api: bool,
    api_fallback: Callable[[str], str | None] | None = None,
) -> str | None:
    """Expand one original template with ordered, explicitly bound providers.

    Keys include their percent delimiters. Provider values and API results are
    copied once, without recursively parsing them. ``None`` input or an API
    failure returns ``None``; an empty successful result returns ``""``.
    Missing API configuration raises only when fallback is actually needed.
    See ORIGINAL_ENV_EXPANSION_PROFILE for locale and resource preconditions.
    """
    if input is None:
        return None
    source = _u16_cstr(input)
    output: list[int] = []
    cursor = 0
    while cursor < len(source):
        if source[cursor] != 0x25:
            output.append(source[cursor])
            cursor += 1
            continue
        end = cursor + 1
        while end < len(source) and source[end] != 0x25:
            end += 1
        if end == len(source):
            output.extend(source[cursor:])
            break
        token = source[cursor : end + 1]
        if end == cursor + 1:
            output.extend(token)
            cursor = end + 1
            continue
        value = _find_value(profile_entries, token)
        if value is None:
            value = _find_value(system_entries, token)
        if value is None:
            if not allow_api:
                value = token
            else:
                if api_fallback is None:
                    raise MissingEnvironmentApiBackend(
                        "unresolved environment token requires api_fallback"
                    )
                expanded = api_fallback(_text(token))
                if expanded is None:
                    return None
                value = _u16_cstr(expanded)
        output.extend(value)
        cursor = end + 1
    return _text(output)
