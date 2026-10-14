from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from .bm_yara import BmYaraRender

Field = tuple[str, str]


@dataclass(slots=True)
class DisplaySection:
    title: str
    rows: tuple[Field, ...] = ()
    bm_yara: "BmYaraRender | None" = None
    printable_preview: str | None = None
    yara_unsupported: tuple[str, ...] = ()


@dataclass(slots=True)
class FormatResult:
    fields: tuple[Field, ...] = ()
    sections: tuple[DisplaySection, ...] = ()


T = TypeVar("T")
Parser = Callable[[bytes], T]
Renderer = Callable[[T], FormatResult]


@dataclass(frozen=True, slots=True)
class FamilySpec[T]:
    type_byte: int
    name: str
    parser: Parser[T]
    renderer: Renderer[T]
