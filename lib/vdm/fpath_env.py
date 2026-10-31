"""Pinned QueryPathFromEnv callback recipes, without resolving runtime paths."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from .env_expand import ORIGINAL_ENV_EXPANSION_PROFILE
from .path_virtualize import ORIGINAL_PATH_VIRTUALIZATION_PROFILE

QUERY_PATH_FROM_ENV: Final = 0x1800C86B0
_ORIGINAL_ENV_ROWS: Final = MappingProxyType(
    {
        24: ("%programdata%", "%ProgramData%"),
        26: ("%windows%", "%windir%"),
        28: ("%program_files%", "%ProgramFiles%"),
        39: ("%CSIDLResources%", "%windir%\\resources"),
        41: ("%program_filesx86%", "%ProgramFiles(x86)%"),
        42: ("%program_filescommon%", "%ProgramFiles%\\common"),
        43: ("%username%", "%username%"),
        44: ("%systemdrive%", "%systemdrive%"),
        45: ("%commonfiles%", "%CommonProgramFiles%"),
        46: ("%allusersprofile%", "%allusersprofile%"),
        47: ("%temp%", "%temp%"),
    }
)


@dataclass(frozen=True, slots=True)
class OriginalEnvRecipe:
    """One original row's provider call plan, not a concrete expansion result."""

    row_index: int
    prefix: str
    template: str

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "callback_control_flow_recipe",
            "coverage": "subset",
            "callback": "QueryPathFromEnv",
            "callback_va": QUERY_PATH_FROM_ENV,
            "row_index": self.row_index,
            "prefix": {"row_offset": 0, "text": self.prefix},
            "template": {
                "row_offset": 8,
                "encoding": "utf-16le",
                "nul_terminated": True,
                "text": self.template,
                "bytes_hex": (self.template.encode("utf-16le") + b"\0\0").hex(),
            },
            "preconditions": ["row_template_pointer_and_output_pointer_nonnull"],
            "runtime_inputs": ["profile", "caller_flags", "prior_out"],
            "inputs_scope": "direct_callback_inputs",
            "provider_runtime_state": "explicit_runtime_bindings_required",
            "caller_flags_source": "runtime_caller_not_vdm_payload_header",
            "provider_contract": {
                "ExpandEnvStrings": {
                    "fixed_flags": 7,
                    "nonnull_result_requires_global_context_and_template_nonnull": True,
                    "system_environment_wrapper_requested": True,
                    "profile_route": (
                        "nonnull_profile_and_successful_GetDataFromHandle_use_"
                        "resolved_profile_plus_0x40_otherwise_empty_profile_wrapper"
                    ),
                    "ExpandEnvrPaths_boolean": "not_bit0_of_global_context_byte_0x2f0",
                    "conditional_text_algorithm": {
                        "callable": "lib.vdm.env_expand.expand_original_env_template",
                        "profile": {
                            key: list(value) if isinstance(value, tuple) else value
                            for key, value in ORIGINAL_ENV_EXPANSION_PROFILE.items()
                        },
                        "runtime_bindings": {
                            "profile_entries": "ordered_entries_of_resolved_profile_wrapper",
                            "system_entries": "ordered_entries_of_system_wrapper",
                            "allow_api": "not_bit0_of_global_context_byte_0x2f0",
                            "api_fallback": "explicit_CallExpandAPI_text_or_null_backend",
                            "CRT_state": "locale_changed_flag_must_be_zero",
                        },
                    },
                    "expanded_result": "unresolved",
                },
                "VirtualizeSimplePath": {
                    "caller_flags": "forwarded_unchanged",
                    "fifth_argument": 1,
                    "conditional_path_algorithm": {
                        "callable": "lib.vdm.path_virtualize.virtualize_simple_path",
                        "profile": {
                            key: list(value) if isinstance(value, tuple) else value
                            for key, value in ORIGINAL_PATH_VIRTUALIZATION_PROFILE.items()
                        },
                        "caller_context": {
                            "initial_paths": [],
                            "output_cleanup_marker": 0,
                            "reason": "FreeExpandedData_clears_output_before_call",
                            "consume_input": True,
                        },
                        "runtime_bindings": [
                            "dynamic_global_context_and_distinct_UTF16_prefix_counts",
                            "offline_scan_and_OS_query_results_in_original_call_order",
                            "dynamic_profile_resolution_raw_return_AL_and_nonnull_view_release",
                            "profile_required_pointer_states_flags_b8_and_base_b0",
                            "ordered_dynamic_profile_enumeration_and_cursor_close",
                            "explicit_WOW_candidate_provider_when_gate_is_one",
                        ],
                    },
                    "actual_runtime_paths": "unresolved",
                },
            },
            "ordered_operations": [
                {
                    "call": "ExpandEnvStrings",
                    "arguments": ["profile", "template", 7],
                    "result": "expanded_or_null",
                },
                {
                    "if": "expanded_or_null_is_null",
                    "operations": [{"effect": "preserve_prior_out"}, {"return": 3}],
                },
                {
                    "if": "expanded_or_null_is_nonnull",
                    "operations": [
                        {
                            "call": "FreeExpandedData",
                            "arguments": ["out"],
                            "effect": "conditionally_release_items_and_list_then_clear_40_bytes",
                            "release_condition": {
                                "offset_base": "out",
                                "all": [
                                    {
                                        "offset": 0x10,
                                        "width": 8,
                                        "comparison": "eq",
                                        "value": 0,
                                    },
                                    {
                                        "offset": 8,
                                        "width": 8,
                                        "comparison": "ne",
                                        "value": 0,
                                    },
                                ],
                            },
                            "release_iteration": {
                                "count": {"offset": 0, "width": 4, "signed": False},
                                "items": "free_nonnull_pointers_in_list_order",
                                "free_list_after_items": True,
                            },
                            "clear": {"offset": 0, "length": 40, "unconditional": True},
                        },
                        {
                            "call": "VirtualizeSimplePath",
                            "arguments": [
                                "profile",
                                "caller_flags",
                                "expanded_or_null",
                                "out",
                                1,
                            ],
                            "result": "virtualizer_status",
                        },
                        {"return": "virtualizer_status"},
                    ],
                },
            ],
            "paths_materialized": False,
            "unresolved_providers": [
                "ExpandEnvrPaths_runtime_environment_bindings_and_API_backend",
                "VirtualizeSimplePath_runtime_bindings_WOW_candidates_and_reference_effects",
            ],
            "initialized_engine_executed": False,
        }


def original_env_recipe_for_row(index: int) -> OriginalEnvRecipe | None:
    """Return the original callback recipe for a row, without selecting that row.

    Callers choose a row using their actual consumer's lookup contract. In
    particular, FPATH must not select rows by linear selector membership.
    """
    if type(index) is not int:
        raise TypeError("predefined path row index must be an integer, excluding bool")
    if not 0 <= index < 49:
        raise ValueError("predefined path row index must be in 0..48")
    fact = _ORIGINAL_ENV_ROWS.get(index)
    return None if fact is None else OriginalEnvRecipe(index, *fact)
