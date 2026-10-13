from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

Field = tuple[str, str]


@dataclass(slots=True)
class DisplaySection:
    title: str
    rows: tuple[Field, ...] = ()


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
