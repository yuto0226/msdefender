from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

from .core import FamilySpec
from .types.aggregator import AGGREGATOR_SPECS
from .types.bm_info import SPEC as BM_INFO_SPEC
from .types.boot import BOOT_SPEC
from .types.brute import SPEC as BRUTE_SPEC
from .types.ck import CK_SPECS
from .types.cleanscript import SPEC as CLEANSCRIPT_SPEC
from .types.common_code import SPEC as COMMON_CODE_SPEC
from .types.dbvar import SPEC as DBVAR_SPEC
from .types.fop import FOP_SPECS
from .types.fpath import FPATH_SPECS
from .types.friendlyfile import SPEC as FRIENDLYFILE_SHA256_SPEC
from .types.hostsentry import SPEC as HOSTSENTRY_SPEC
from .types.hstr import HSTR_SPECS
from .types.il2_pattern import SPEC as IL2_PATTERN_SPEC
from .types.kcrce import SPEC as KCRCE_SPEC
from .types.kpat import KPAT_SPEC, KPATEX_SPEC
from .types.kvir32 import SPEC as KVIR32_SPEC
from .types.latent_threat import SPEC as LATENT_THREAT_SPEC
from .types.lua_standalone import SPEC as LUASTANDALONE_SPEC
from .types.macro_pcode import MACRO_PCODE_SPECS
from .types.macro_source import SPEC as MACRO_SOURCE_SPEC
from .types.magiccode import SPEC as MAGICCODE_SPEC
from .types.ndat import NDAT_SPEC
from .types.nid import NID_SPECS
from .types.nscript import NSCRIPT_SPECS
from .types.pattmatch import SPEC as PATTMATCH_SPEC
from .types.pebmpat import SPEC as PEBMPAT_SPEC
from .types.pefile_cure import SPEC as PEFILE_CURE_SPEC
from .types.pestatic import SPEC as PESTATIC_SPEC
from .types.regkey import SPEC as REGKEY_SPEC
from .types.revoked_certificate import SPEC as REVOKED_CERTIFICATE_SPEC
from .types.sigtree import SIGTREE_BM_SPEC, SIGTREE_EXT_SPEC, SIGTREE_SPEC
from .types.snidex import SNIDEX_SPECS
from .types.static import SPEC as STATIC_SPEC
from .types.threat import THREAT_SPECS
from .types.trusted_publisher import SPEC as TRUSTED_PUBLISHER_SPEC
from .types.vdll_code import FAMILY_SPECS as VDLL_CODE_SPECS
from .types.vdll_meta import FAMILY_SPECS as VDLL_META_SPECS
from .types.versioncheck import SPEC as VERSIONCHECK_SPEC
from .types.vreg import SPEC as VREG_SPEC

DEFAULT_REGISTRY: Mapping[int, FamilySpec[Any]] = MappingProxyType(
    {
        spec.type_byte: spec
        for spec in (
            REGKEY_SPEC,
            REVOKED_CERTIFICATE_SPEC,
            *AGGREGATOR_SPECS,
            TRUSTED_PUBLISHER_SPEC,
            LATENT_THREAT_SPEC,
            LUASTANDALONE_SPEC,
            MACRO_SOURCE_SPEC,
            *MACRO_PCODE_SPECS,
            VERSIONCHECK_SPEC,
            COMMON_CODE_SPEC,
            CLEANSCRIPT_SPEC,
            DBVAR_SPEC,
            VREG_SPEC,
            SIGTREE_SPEC,
            SIGTREE_EXT_SPEC,
            KVIR32_SPEC,
            *SNIDEX_SPECS,
            BM_INFO_SPEC,
            BOOT_SPEC,
            BRUTE_SPEC,
            *CK_SPECS,
            FRIENDLYFILE_SHA256_SPEC,
            SIGTREE_BM_SPEC,
            STATIC_SPEC,
            KCRCE_SPEC,
            KPAT_SPEC,
            KPATEX_SPEC,
            IL2_PATTERN_SPEC,
            MAGICCODE_SPEC,
            HOSTSENTRY_SPEC,
            PESTATIC_SPEC,
            PEBMPAT_SPEC,
            PATTMATCH_SPEC,
            PEFILE_CURE_SPEC,
            *FPATH_SPECS,
            *FOP_SPECS,
            *THREAT_SPECS,
            *HSTR_SPECS,
            *NID_SPECS,
            NDAT_SPEC,
            *NSCRIPT_SPECS,
            *VDLL_META_SPECS,
            *VDLL_CODE_SPECS,
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
