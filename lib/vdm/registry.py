from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

from .core import FamilySpec
from .types.bm_info import SPEC as BM_INFO_SPEC

DEFAULT_REGISTRY: Mapping[int, FamilySpec[Any]] = MappingProxyType(
    {BM_INFO_SPEC.type_byte: BM_INFO_SPEC}
)


def build_registry(
    specs: Iterable[FamilySpec[Any]],
) -> dict[int, FamilySpec[Any]]:
    registry: dict[int, FamilySpec[Any]] = {}
    for spec in specs:
        if spec.type_byte in registry:
            raise ValueError(f"Duplicate VDM type byte 0x{spec.type_byte:02X}")
        registry[spec.type_byte] = spec
    return registry


def get_spec(
    type_byte: int,
    registry: Mapping[int, FamilySpec[Any]] | None = None,
) -> FamilySpec[Any] | None:
    if registry is None:
        registry = DEFAULT_REGISTRY
    return registry.get(type_byte)
