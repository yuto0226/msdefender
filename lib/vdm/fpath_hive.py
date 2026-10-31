"""Pinned Hive callback recipes and raw system-CSIDL query descriptors.

This module describes original rows and call contracts. It does not read the
registry, create environment lists, resolve opaque profiles or materialize paths.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from .env_expand import ORIGINAL_ENV_EXPANSION_PROFILE
from .path_virtualize import ORIGINAL_PATH_VIRTUALIZATION_PROFILE

QUERY_PATH_FROM_HIVE: Final = 0x1800C8330
_ORIGINAL_HIVE_ROWS: Final = MappingProxyType(
    {
        0: (
            "%programs%",
            "%Programs%",
            "d0a8db8001000000e8a8db8001000000010000000000000030830c80010000000200000000000000",
        ),
        1: (
            "%mydocuments%",
            "%Personal%",
            "00a9db800100000020a9db8001000000010000000000000030830c80010000000500000000000000",
        ),
        2: (
            "%favorites%",
            "%Favorites%",
            "38a9db800100000050a9db8001000000010000000000000030830c80010000000600000000000000",
        ),
        3: (
            "%startup%",
            "%Startup%",
            "68a9db800100000080a9db8001000000010000000000000030830c80010000000700000000000000",
        ),
        4: (
            "%recent%",
            "%Recent%",
            "98a9db8001000000b0a9db8001000000010000000000000030830c80010000000800000000000000",
        ),
        5: (
            "%sendto%",
            "%SendTo%",
            "c8a9db8001000000e0a9db8001000000010000000000000030830c80010000000900000000000000",
        ),
        6: (
            "%startmenu%",
            "%Start Menu%",
            "f8a9db800100000010aadb8001000000010000000000000030830c80010000000b00000000000000",
        ),
        7: (
            "%mymusic%",
            "%My Music%",
            "30aadb800100000048aadb8001000000010000000000000030830c80010000000d00000000000000",
        ),
        8: (
            "%myvideo%",
            "%My Video%",
            "60aadb800100000078aadb8001000000010000000000000030830c80010000000e00000000000000",
        ),
        9: (
            "%desktopdirectory%",
            "%Desktop%",
            "90aadb8001000000b8aadb8001000000010000000000000030830c80010000001000000000000000",
        ),
        10: (
            "%nethood%",
            "%NetHood%",
            "d0aadb8001000000e8aadb8001000000010000000000000030830c80010000001300000000000000",
        ),
        11: (
            "%fonts%",
            "%Fonts%",
            "00abdb800100000010abdb8001000000010000000000000030830c80010000001400000000000000",
        ),
        12: (
            "%templates%",
            "%Templates%",
            "20abdb800100000038abdb8001000000010000000000000030830c80010000001500000000000000",
        ),
        13: (
            "%common_startmenu%",
            "%Common Start Menu%",
            "50abdb800100000078abdb8001000000000000000000000030830c80010000001600000000000000",
        ),
        14: (
            "%common_programs%",
            "%Common Programs%",
            "a0abdb8001000000c8abdb8001000000000000000000000030830c80010000001700000000000000",
        ),
        15: (
            "%common_startup%",
            "%Common Startup%",
            "f0abdb800100000018acdb8001000000000000000000000030830c80010000001800000000000000",
        ),
        16: (
            "%common_desktop%",
            "%Common Desktop%",
            "40acdb800100000068acdb8001000000000000000000000030830c80010000001900000000000000",
        ),
        17: (
            "%appdata%",
            "%AppData%",
            "c0fbde800100000090acdb8001000000010000000000000030830c80010000001a00000000000000",
        ),
        18: (
            "%printhood%",
            "%PrintHood%",
            "a8acdb8001000000c0acdb8001000000010000000000000030830c80010000001b00000000000000",
        ),
        19: (
            "%localappdata%",
            "%Local AppData%",
            "d8fbde8001000000d8acdb8001000000010000000000000030830c80010000001c00000000000000",
        ),
        20: (
            "%common_favorites%",
            "%Common Favorites%",
            "f8acdb800100000020addb8001000000000000000000000030830c80010000001f00000000000000",
        ),
        21: (
            "%internet_cache%",
            "%Cache%",
            "48addb800100000070addb8001000000010000000000000030830c80010000002000000000000000",
        ),
        22: (
            "%cookies%",
            "%Cookies%",
            "80addb800100000098addb8001000000010000000000000030830c80010000002100000000000000",
        ),
        23: (
            "%history%",
            "%History%",
            "b0addb8001000000c8addb8001000000010000000000000030830c80010000002200000000000000",
        ),
        25: (
            "%common_appdata%",
            "%Common AppData%",
            "00aedb800100000028aedb8001000000000000000000000030830c80010000002300000000000000",
        ),
        29: (
            "%mypictures%",
            "%My Pictures%",
            "88aedb8001000000a8aedb8001000000010000000000000030830c80010000002700000000000000",
        ),
        31: (
            "%common_templates%",
            "%Common Templates%",
            "c8aedb8001000000f0aedb8001000000000000000000000030830c80010000002d00000000000000",
        ),
        32: (
            "%common_documents%",
            "%Common Documents%",
            "18afdb800100000040afdb8001000000000000000000000030830c80010000002e00000000000000",
        ),
        33: (
            "%common_admin_tools%",
            "%Common Administrative Tools%",
            "68afdb800100000098afdb8001000000000000000000000030830c80010000002f00000000000000",
        ),
        34: (
            "%admin_tools%",
            "%Administrative Tools%",
            "d8afdb8001000000f8afdb8001000000010000000000000030830c80010000003000000000000000",
        ),
        35: (
            "%common_music%",
            "%CommonMusic%",
            "28b0db800100000048b0db8001000000000000000000000030830c80010000003500000000000000",
        ),
        36: (
            "%common_pictures%",
            "%CommonPictures%",
            "68b0db800100000090b0db8001000000000000000000000030830c80010000003600000000000000",
        ),
        37: (
            "%common_video%",
            "%CommonVideo%",
            "b8b0db8001000000d8b0db8001000000000000000000000030830c80010000003700000000000000",
        ),
        38: (
            "%cd_burn%",
            "%CD Burning%",
            "f8b0db800100000010b1db8001000000010000000000000030830c80010000003b00000000000000",
        ),
        40: (
            "%CSIDLPersonal%",
            "%Personal%",
            "80b1db800100000020a9db8001000000010000000000000030830c80010000000500000000000000",
        ),
    }
)


@dataclass(frozen=True, slots=True)
class SystemCSIDLQueryDescriptor:
    """One original 24-byte provider descriptor; unnamed fields stay raw."""

    index: int
    subkey_va: int
    subkey: str
    raw_hex: str
    raw_arg5_u64: int = 0
    raw_arg6_u64: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "index": self.index,
            "table_va": 0x180DF26A0,
            "stride_bytes": 24,
            "raw_hex": self.raw_hex,
            "subkey": {
                "row_offset": 0,
                "width_bytes": 8,
                "pointer_va": self.subkey_va,
                "encoding": "utf-16le",
                "nul_terminated": True,
                "text": self.subkey,
            },
            "raw_arg5": {"row_offset": 8, "width_bytes": 8, "value": self.raw_arg5_u64},
            "raw_arg6": {
                "row_offset": 16,
                "width_bytes": 8,
                "value": self.raw_arg6_u64,
            },
            "builder_call": {
                "root_hkey_u64": 0xFFFFFFFF80000002,
                "root_symbol": "HKEY_LOCAL_MACHINE",
                "offline_null": "WrapHKEYIntoRegistryKey(root, out_key)",
                "offline_nonnull": "CallistoGetVirtualizedKey(offline, root, subkey, out_key, out_suffix_offset)",
                "suffix_offset": {"width_bytes": 8, "unit": "UTF-16_code_units"},
                "AddEnvrFromReg_arguments": [
                    "out_temporary_entry",
                    "inout_list",
                    "provider_key",
                    "subkey_plus_provider_suffix_offset",
                    self.raw_arg5_u64,
                    self.raw_arg6_u64,
                    "offline_data",
                    0,
                ],
                "argument_8_width_bytes": 4,
                "status_mapping": "RemapErrorCode(3, provider_status); nonzero_stops",
            },
            "provider_body": "unmodeled",
        }


ORIGINAL_SYSTEM_CSIDL_QUERIES: Final = (
    SystemCSIDLQueryDescriptor(
        0,
        0x180DF2830,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "3028df800100000000000000000000000000000000000000",
    ),
    SystemCSIDLQueryDescriptor(
        1,
        0x180E602B0,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        "b002e6800100000000000000000000000000000000000000",
    ),
)


@dataclass(frozen=True, slots=True)
class OriginalHiveRecipe:
    """One original callback row, without selecting it or running providers."""

    row_index: int
    prefix: str
    template: str
    raw_row_hex: str

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "callback_control_flow_recipe",
            "coverage": "subset",
            "callback": "QueryPathFromHive",
            "callback_va": QUERY_PATH_FROM_HIVE,
            "row_index": self.row_index,
            "raw_row_hex": self.raw_row_hex,
            "prefix": {"row_offset": 0, "text": self.prefix},
            "template": {
                "row_offset": 8,
                "encoding": "utf-16le",
                "nul_terminated": True,
                "text": self.template,
                "bytes_hex": (self.template.encode("utf-16le") + b"\0\0").hex(),
            },
            "preconditions": ["valid_row_template_and_output_pointers"],
            "runtime_inputs": ["profile", "caller_flags", "prior_out"],
            "caller_flags_source": "runtime_caller_not_vdm_payload_header",
            "provider_runtime_state": "explicit_runtime_bindings_required",
            "provider_contract": {
                "ExpandCSIDLString": {
                    "nonnull_result_requires_global_context_and_template_nonnull": True,
                    "system_list": {
                        "GetEnvVar_type": 1,
                        "cached_global_context_offset": 0x68,
                        "wrapper_getter_ignores_GetEnvVar_boolean": True,
                        "query_providers": [
                            q.to_json() for q in ORIGINAL_SYSTEM_CSIDL_QUERIES
                        ],
                    },
                    "profile_route": {
                        "GetDataFromHandle_user_output": None,
                        "GetDataFromHandle_profile_output": "temporary_resolved_profile",
                        "success": "raw_return_low_byte_nonzero",
                        "success_wrapper_offset": 0x48,
                        "null_handle_or_failed_resolution": "empty_profile_CSIDL_wrapper",
                        "nonnull_failed_view": "release_before_empty_profile_expansion",
                        "release_order_success": [
                            "resolved_profile",
                            "system_CSIDL_list",
                        ],
                    },
                    "allow_api": False,
                    "conditional_text_algorithm": {
                        "callable": "lib.vdm.env_expand.expand_original_env_template",
                        "profile": {
                            key: list(value) if isinstance(value, tuple) else value
                            for key, value in ORIGINAL_ENV_EXPANSION_PROFILE.items()
                        },
                        "profile_entries": "resolved_profile_CSIDL_wrapper_at_0x48",
                        "system_entries": "GetEnvVar_type_1_CSIDL_list",
                        "allow_api": False,
                    },
                },
                "ExpandEnvStrings": {
                    "called_only_when": "CSIDL_result_differs_and_contains_percent",
                    "fixed_flags": 7,
                    "system_list": {
                        "GetEnvVar_type": 0,
                        "cached_global_context_offset": 0x60,
                    },
                    "resolved_profile_wrapper_offset": 0x40,
                    "allow_api": "not_bit0_of_global_context_byte_0x2f0",
                    "environment_and_API_backend": "explicit_runtime_bindings_required",
                },
                "VirtualizeSimplePath": {
                    "callable": "lib.vdm.path_virtualize.virtualize_simple_path",
                    "profile": {
                        key: list(value) if isinstance(value, tuple) else value
                        for key, value in ORIGINAL_PATH_VIRTUALIZATION_PROFILE.items()
                    },
                    "caller_flags": "forwarded_unchanged",
                    "fifth_argument": 1,
                    "caller_context": {
                        "initial_paths": [],
                        "output_cleanup_marker": 0,
                        "consume_input": True,
                        "reason": "first_nonnull_result_clears_prior_output",
                    },
                    "actual_runtime_paths": "unresolved",
                },
            },
            "ordered_operations": [
                {
                    "call": "ExpandCSIDLString",
                    "arguments": ["profile", "template"],
                    "result": "csidl_result",
                },
                {
                    "if": "csidl_result_is_null",
                    "operations": [{"effect": "preserve_prior_out"}, {"return": 3}],
                },
                {
                    "if": "csidl_result_is_nonnull",
                    "operations": [
                        {
                            "call": "FreeExpandedData",
                            "arguments": ["out"],
                            "effect": "conditional_owned_release_then_clear_40_bytes",
                        },
                        {
                            "call": "_wcsicmp",
                            "arguments": ["csidl_result", "template"],
                            "result": "comparison",
                        },
                        {
                            "if": "comparison_is_zero",
                            "operations": [
                                {"call": "free", "arguments": ["csidl_result"]},
                                {"return": 2},
                            ],
                        },
                        {
                            "if": "comparison_is_nonzero",
                            "operations": [
                                {
                                    "if": "csidl_result_contains_any_percent",
                                    "operations": [
                                        {
                                            "call": "ExpandEnvStrings",
                                            "arguments": ["profile", "csidl_result", 7],
                                            "result": "env_result",
                                        },
                                        {"call": "free", "arguments": ["csidl_result"]},
                                        {
                                            "if": "env_result_is_null",
                                            "operations": [{"return": 3}],
                                        },
                                        {"effect": "final_input_is_nonnull_env_result"},
                                    ],
                                },
                                {
                                    "if": "csidl_result_contains_no_percent",
                                    "effect": "final_input_is_csidl_result",
                                },
                                {
                                    "call": "VirtualizeSimplePath",
                                    "arguments": [
                                        "profile",
                                        "caller_flags",
                                        "final_input",
                                        "out",
                                        1,
                                    ],
                                    "result": "virtualizer_status",
                                },
                                {"return": "virtualizer_status"},
                            ],
                        },
                    ],
                },
            ],
            "paths_materialized": False,
            "initialized_engine_executed": False,
            "unresolved_providers": [
                "registry_value_types_enumeration_token_packaging_and_list_contents",
                "profile_CSIDL_and_environment_list_runtime_sources",
                "opaque_profile_resolution_and_physical_references",
                "ordinary_environment_API_backend_and_virtualizer_runtime_bindings",
            ],
        }


def original_hive_recipe_for_row(index: int) -> OriginalHiveRecipe | None:
    """Get a row fact; callers must select by their actual consumer's lookup."""
    if type(index) is not int:
        raise TypeError("predefined path row index must be an integer, excluding bool")
    if not 0 <= index < 49:
        raise ValueError("predefined path row index must be in 0..48")
    fact = _ORIGINAL_HIVE_ROWS.get(index)
    return None if fact is None else OriginalHiveRecipe(index, *fact)
