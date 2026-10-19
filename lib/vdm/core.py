import math
from collections.abc import Callable
from dataclasses import dataclass
from types import NoneType
from typing import TYPE_CHECKING, Literal, TypeVar

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

type JSONValue = NoneType | bool | int | float | str | tuple[JSONValue, ...]
type JSONDetails = tuple[tuple[str, JSONValue], ...]


def _validate_json_value(value: JSONValue) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("artifact warning values must be finite JSON numbers")
        return
    if isinstance(value, tuple):
        for item in value:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                if not item[0]:
                    raise ValueError("artifact warning object keys must be non-empty")
                _validate_json_value(item[1])
            else:
                _validate_json_value(item)
        object_items = [
            item
            for item in value
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
        ]
        if object_items and len(object_items) == len(value):
            keys = [item[0] for item in object_items]
            if len(keys) != len(set(keys)):
                raise ValueError("artifact warning object keys must be unique")
        return
    raise TypeError(
        f"artifact warning value is not immutable JSON data: {type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    kind: str
    data: bytes

    def __post_init__(self) -> None:
        stem = self.name.split(".", 1)[0].rstrip(" ").casefold()
        reserved_stems = {"con", "prn", "aux", "nul", "conin$", "conout$"}
        numbered_device = (
            len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789¹²³"
        )
        if (
            not self.name
            or self.name in {".", ".."}
            or self.name.endswith((".", " "))
            or stem in reserved_stems
            or numbered_device
            or any(char in self.name for char in '/\\<>:"|?*')
            or any(ord(char) < 32 for char in self.name)
        ):
            raise ValueError("artifact name must be a safe local filename")


@dataclass(frozen=True, slots=True)
class ArtifactWarning:
    code: str
    message: str
    details: JSONDetails = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not isinstance(self.message, str):
            raise TypeError("artifact warning code and message must be strings")
        if not self.code or not self.message:
            raise ValueError("artifact warning code and message must be non-empty")
        if not isinstance(self.details, tuple):
            raise TypeError("artifact warning details must be an immutable tuple")
        keys: list[str] = []
        for entry in self.details:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("artifact warning details must contain key/value pairs")
            key, value = entry
            if not isinstance(key, str):
                raise TypeError("artifact warning detail keys must be strings")
            if not key:
                raise ValueError(
                    "artifact warning detail keys must be non-empty strings"
                )
            keys.append(key)
            _validate_json_value(value)
        if len(keys) != len(set(keys)):
            raise ValueError("artifact warning detail keys must be unique")


@dataclass(frozen=True, slots=True)
class ArtifactExport:
    status: Literal["ready", "unsupported"]
    artifacts: tuple[Artifact, ...] = ()
    warnings: tuple[ArtifactWarning, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        names = [artifact.name.casefold() for artifact in self.artifacts]
        if len(names) != len(set(names)):
            raise ValueError("artifact names must be unique")
        if self.status == "unsupported" and self.artifacts:
            raise ValueError("unsupported artifact export cannot contain artifacts")
        if self.status == "ready" and not self.artifacts:
            raise ValueError("ready artifact export must contain artifacts")


@dataclass(frozen=True, slots=True)
class FamilySpec[T]:
    type_byte: int
    name: str
    parser: Parser[T]
    renderer: Renderer[T]
    exporter: Callable[[T], ArtifactExport] | None = None
