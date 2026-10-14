from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

from .core import FamilySpec
from .types.bm_info import SPEC as BM_INFO_SPEC
from .types.hstr import HSTR_SPECS
from .types.sigtree import SIGTREE_BM_SPEC, SIGTREE_EXT_SPEC, SIGTREE_SPEC
from .types.threat import THREAT_SPECS

DEFAULT_REGISTRY: Mapping[int, FamilySpec[Any]] = MappingProxyType(
    {
        spec.type_byte: spec
        for spec in (
            SIGTREE_SPEC,
            SIGTREE_EXT_SPEC,
            BM_INFO_SPEC,
            SIGTREE_BM_SPEC,
            *THREAT_SPECS,
            *HSTR_SPECS,
        )
    }
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
