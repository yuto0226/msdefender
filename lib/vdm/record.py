from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .core import FamilySpec, FormatResult
from .registry import get_spec

if TYPE_CHECKING:
    from lib.terminal import RenderContext


@dataclass(frozen=True, slots=True)
class DecodedRecord:
    type_byte: int
    raw: bytes
    spec: FamilySpec[Any] | None
    value: Any | None = None
    error: str | None = None

    def _format_result(self) -> FormatResult:
        if self.spec is None:
            return FormatResult()
        if self.error is not None:
            return FormatResult(fields=(("Error", self.error),))
        return self.spec.renderer(self.value)

    def render(self, context: "RenderContext") -> str:
        from lib.terminal._renderer import render_record

        return render_record(self, context)


def decode_record(
    type_byte: int,
    payload: bytes,
    registry: Mapping[int, FamilySpec[Any]] | None = None,
) -> DecodedRecord:
    spec = get_spec(type_byte, registry)
    if spec is None:
        return DecodedRecord(type_byte=type_byte, raw=payload, spec=None)

    try:
        value = spec.parser(payload)
    except ValueError as exc:
        return DecodedRecord(
            type_byte=type_byte,
            raw=payload,
            spec=spec,
            error=str(exc),
        )
    return DecodedRecord(type_byte=type_byte, raw=payload, spec=spec, value=value)
