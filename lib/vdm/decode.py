from collections.abc import Mapping
from typing import Any

from .core import FamilySpec, FormatResult
from .registry import get_spec


def decode_payload(
    type_byte: int,
    payload: bytes,
    registry: Mapping[int, FamilySpec[Any]] | None = None,
) -> FormatResult:
    spec = get_spec(type_byte, registry)
    if spec is None:
        return FormatResult()

    try:
        parsed = spec.parser(payload)
    except ValueError as exc:
        return FormatResult(fields=(("Error", str(exc)),))
    return spec.renderer(parsed)
