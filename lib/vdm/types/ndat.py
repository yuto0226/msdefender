"""Parser and renderer for NDAT (0xA9) payloads."""

import hashlib
import json
from dataclasses import dataclass
from typing import Final

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
    semantic_json_to_data,
)
from ..raw_body import (
    RawBodyPattern,
    UnsupportedRawBodyPattern,
    compile_raw_body_pattern,
    render_raw_body_yara,
)
from ..raw_ssl_cert import (
    RawSslBytePattern,
    UnsupportedRawSslPattern,
    compile_raw_ssl_byte_pattern,
    raw_ssl_yara_rhs,
)
from ..vdll_api_attribute import ApiAttributeProjection, project_api_attribute
from ..vdll_api_membership import VdllApiProjection, project_vdll_api
from ..vdll_fire_event import (
    FireEventRecipe,
    UnsupportedFireEvent,
    project_fire_event_recipe,
)
from ..vfs_link import VfsLinkProjection, project_vfs_link

NDAT_TYPE: Final = 0xA9
PREVIEW_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class NdatPayload:
    """NDAT wire fields consumed by ``ReceiveNewTemplate``."""

    raw: bytes
    data_length: int
    data_raw: bytes
    callback_index: int
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


class UnsupportedNdatApiAttribute(ValueError):
    """The authoritative raw NDAT record is not callback7 API metadata."""


@dataclass(frozen=True, slots=True)
class NdatApiAttribute:
    """Wire byte projection, without initialized tables or stored pointers."""

    raw: bytes
    counted_data: bytes
    projection: ApiAttributeProjection
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


def project_ndat_api_attribute(parsed: NdatPayload) -> NdatApiAttribute:
    """Reparse callback7 raw bytes; ordinary parse skips remain metadata."""
    if not isinstance(parsed, NdatPayload):
        raise TypeError("parsed must be NdatPayload")
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 7:
        raise UnsupportedNdatApiAttribute("requires callback decimal7 (0x07)")
    return NdatApiAttribute(
        parsed.raw,
        parsed.data_raw,
        project_api_attribute(parsed.data_raw, parsed.data_length),
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _api_attribute_manifest(parsed: NdatPayload) -> JSONObject:
    model = project_ndat_api_attribute(parsed)
    p, api = model.projection, model.projection.api
    ordinal = p.ordinal
    recipe_paths = (
        ("projector", "lib.vdm.types.ndat.project_ndat_api_attribute"),
        ("model_type", "lib.vdm.types.ndat.NdatApiAttribute"),
        ("unsupported_type", "lib.vdm.types.ndat.UnsupportedNdatApiAttribute"),
        ("pair_projector", "lib.vdm.vdll_api_attribute.project_api_attribute"),
        ("projection_type", "lib.vdm.vdll_api_attribute.ApiAttributeProjection"),
        ("resolver", "lib.vdm.vdll_api_attribute.resolve_api_attribute"),
        ("store_outcome_type", "lib.vdm.vdll_api_attribute.ApiAttributeStoreOutcome"),
        ("stored_value_type", "lib.vdm.vdll_api_attribute.ApiAttributeStoredValue"),
        ("store_request_type", "lib.vdm.vdll_api_attribute.ApiAttributeStoreRequest"),
        ("resolution_type", "lib.vdm.vdll_api_attribute.ApiAttributeResolution"),
        (
            "callback_projection_type",
            "lib.vdm.vdll_api_attribute.ApiAttributeCallbackProjection",
        ),
        ("map_type", "lib.vdm.vdll_api_attribute.ApiAttributeMapSnapshot"),
        ("map_entry_type", "lib.vdm.vdll_api_attribute.ApiAttributeMapEntry"),
        ("map_lookup", "lib.vdm.vdll_api_attribute.ApiAttributeMapSnapshot.lookup"),
        (
            "consumer_projector",
            "lib.vdm.vdll_api_attribute.project_api_attribute_consumer",
        ),
        (
            "consumer_projection_type",
            "lib.vdm.vdll_api_attribute.ApiAttributeConsumerProjection",
        ),
        (
            "aggregate_request_type",
            "lib.vdm.vdll_api_attribute.AggregateApiAttributeRequest",
        ),
        ("state_error_type", "lib.vdm.vdll_api_attribute.UnsupportedApiAttribute"),
        ("host_type", "lib.vdm.vdll_api_membership.VdllApiHost"),
        ("module_selection_type", "lib.vdm.vdll_api_membership.VdllModuleSelection"),
        ("export_table_type", "lib.vdm.vdll_api_membership.VdllExportTable"),
        ("named_export_type", "lib.vdm.vdll_api_membership.VdllNamedExport"),
        ("ordinal_parser", "lib.vdm.vdll_api_membership.parse_vdll_ordinal"),
        ("ordinal_type", "lib.vdm.vdll_api_membership.VdllOrdinal"),
        ("crc", "lib.vdm.vdll_api_membership.vdll_api_crc"),
        ("bucket", "lib.vdm.vdll_api_membership.vdll_api_bucket"),
    )
    return JSONObject(
        (
            ("format", "vdm.ndat.vdll-api-attribute-metadata.v1"),
            ("kind", "engine_vdll_api_attribute_metadata_not_ioc"),
            ("counted_data_hex", model.counted_data.hex()),
            (
                "module_raw_hex",
                None if api.module_name is None else api.module_name.hex(),
            ),
            (
                "copied_selector_raw_hex",
                None if api.selector is None else api.selector.hex(),
            ),
            ("selector_copy_hresult", api.selector_copy_hresult),
            ("delimiter_offset", api.delimiter_offset),
            ("colon_offset", p.colon_offset),
            (
                "selector_before_colon_raw_hex",
                None
                if p.colon_offset is None
                else api.selector[: p.colon_offset].hex(),
            ),
            (
                "attribute_name_raw_hex",
                None if p.attribute_name is None else p.attribute_name.hex(),
            ),
            ("route", api.route),
            ("name_crc_before_colon_u32", p.name_crc),
            (
                "ordinal_from_full_tail",
                None
                if ordinal is None
                else JSONObject(
                    (
                        ("value_u32", ordinal.value),
                        ("hresult", ordinal.hresult),
                        ("end_offset", ordinal.end_offset),
                    )
                ),
            ),
            (
                "wire_parse_skip_reason",
                api.skip_reason
                or ("colon_missing" if p.colon_offset is None else None),
            ),
            (
                "wire_parse_scope",
                "local byte projection only; runtime module binding is consulted before the native colon gate",
            ),
            (
                "record_name_raw_hex",
                None
                if model.record_id_suffix_raw is None
                else model.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", model.trailing_raw.hex()),
            ("runtime_recid_used_by_callback", False),
            ("last_nul_required", False),
            ("stored_value_state", "unknown"),
            ("callback_return", None),
            ("registration_completed", None),
            ("record_local_match", None),
            ("final_verdict", None),
            (
                "recipe",
                JSONObject(
                    (
                        *recipe_paths,
                        (
                            "copy",
                            "counted first ! at1..127, first-NUL copy128; ignored HRESULT; first colon in copied CString",
                        ),
                        (
                            "selector",
                            "named rawCRC only before colon; @ ordinal parser reads full copied tail including colon and attribute, ignores HRESULT, failed out0 still looked up",
                        ),
                        (
                            "bindings",
                            "four explicit host gates and selected VDLL tables; index0 valid, unknown distinct from confirmed miss; resolvedVA nonzero before host2 bit0 clearing, stored0 remains valid",
                        ),
                        (
                            "object_storage",
                            "attribute CString plusNUL, kstore size=len+1 flags0; returned pointer is borrowed object-store value, distinct from raw wire storage; allocator and lifetime remain external",
                        ),
                        (
                            "store_outcomes",
                            "explicit actual kstore call order; missing unknown vs confirmedNULL; NULL stops8007 preserving prior candidates; duplicates still callstore; candidates do not prove map allocation/insertion success",
                        ),
                        (
                            "runtime_maps",
                            "explicit successful history within one caller-confirmed active epoch; first wins per host/fullu64key; no implicit initialization, wire order or liveness proof",
                        ),
                        (
                            "consumer",
                            "static pre-only exact rawu64VA lookup without bit clearing; MpAggregateAttributeEx request uses symbolic EmptySha1, return ignored; DWORD ADD512 wraps, not bitwiseOR; no whole pe_notify or aggregation verdict",
                        ),
                        (
                            "unknown",
                            "actual module bindings/table epoch, original object storage/borrowed lifetime, allocation/exception partial state, complete aggregation and final policy",
                        ),
                    )
                ),
            ),
        )
    )


def _export_api_attribute(parsed: NdatPayload) -> ArtifactExport:
    model = project_ndat_api_attribute(parsed)
    return ArtifactExport(
        "ready",
        (
            Artifact("vdll-api-attribute-data.bin", "binary", model.counted_data),
            Artifact(
                "vdll-api-attribute-metadata.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_api_attribute_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatFireEvent(ValueError):
    """The raw record is not callback4 VDLL event metadata."""


@dataclass(frozen=True, slots=True)
class NdatFireEvent:
    """Wire API input and a conditional name candidate, not a runtime binding."""

    raw: bytes
    counted_data: bytes
    api_projection: VdllApiProjection
    name_recipe_candidate: FireEventRecipe | None
    candidate_issue: str | None
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


def project_ndat_fire_event(parsed: NdatPayload) -> NdatFireEvent:
    """Reparse callback4 raw bytes without inventing getter or map state."""
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 4:
        raise UnsupportedNdatFireEvent("requires callback decimal4 (0x04)")
    candidate, issue = None, None
    if parsed.record_id_suffix_raw is not None:
        try:
            # The named object copy ends at its first NUL: trailing wire bytes
            # are not established readable runtime padding for malformed formats.
            candidate = project_fire_event_recipe(parsed.record_id_suffix_raw)
        except UnsupportedFireEvent as exc:
            issue = str(exc)
    return NdatFireEvent(
        parsed.raw,
        parsed.data_raw,
        project_vdll_api(parsed.data_raw, parsed.data_length),
        candidate,
        issue,
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _fire_event_manifest(parsed: NdatPayload) -> JSONObject:
    model = project_ndat_fire_event(parsed)
    api, candidate = model.api_projection, model.name_recipe_candidate
    ordinal = api.ordinal
    data = None if candidate is None else candidate.data
    candidate_status = (
        "unsupported"
        if model.candidate_issue is not None
        else "absent"
        if candidate is None
        else "parsed_skip"
        if candidate.skip_reason is not None
        else "parsed"
    )
    return JSONObject(
        (
            ("format", "vdm.ndat.vdll-fire-event-metadata.v1"),
            ("kind", "engine_vdll_event_metadata_not_ioc"),
            ("counted_data_hex", model.counted_data.hex()),
            (
                "module_raw_hex",
                None if api.module_name is None else api.module_name.hex(),
            ),
            ("selector_raw_hex", None if api.selector is None else api.selector.hex()),
            ("selector_copy_hresult", api.selector_copy_hresult),
            ("api_skip_reason", api.skip_reason),
            ("api_route", api.route),
            ("api_delimiter_offset", api.delimiter_offset),
            (
                "api_ordinal",
                None
                if ordinal is None
                else JSONObject(
                    (
                        ("value_u32", ordinal.value),
                        ("hresult", ordinal.hresult),
                        ("end_offset", ordinal.end_offset),
                    )
                ),
            ),
            ("name_crc_u32", api.name_crc),
            (
                "record_name_raw_hex",
                None
                if model.record_id_suffix_raw is None
                else model.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", model.trailing_raw.hex()),
            (
                "wire_name_recipe_candidate",
                JSONObject(
                    (
                        ("status", candidate_status),
                        (
                            "evaluation_scope",
                            "independent wire candidate parse, not an executed callback stage or resolved getter value",
                        ),
                        ("issue", model.candidate_issue),
                        ("post", None if candidate is None else candidate.post),
                        (
                            "skip_reason",
                            None if candidate is None else candidate.skip_reason,
                        ),
                        ("packed_hex", None if data is None else data.pack().hex()),
                        ("event_id_u32", None if data is None else data.event_id),
                        (
                            "consumer_event_id_u16",
                            None if data is None else data.event_id & 0xFFFF,
                        ),
                        ("param1_index", None if data is None else data.param1_index),
                        ("param1_type", None if data is None else data.param1_type),
                        ("param2_index", None if data is None else data.param2_index),
                        ("param2_type", None if data is None else data.param2_type),
                        (
                            "condition",
                            "wire suffix is only a candidate; exact runtime name requires successful named-object publication and no shadow/redirect/override; absent candidate is not getter NULL",
                        ),
                    )
                ),
            ),
            ("runtime_name_state", "unknown"),
            ("runtime_recid_used_by_callback", True),
            ("last_nul_required_for_api_data", False),
            ("callback_return", None),
            ("registration_completed", None),
            ("record_local_match", None),
            ("final_verdict", None),
            (
                "recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.types.ndat.project_ndat_fire_event"),
                        ("model_type", "lib.vdm.types.ndat.NdatFireEvent"),
                        (
                            "unsupported_type",
                            "lib.vdm.types.ndat.UnsupportedNdatFireEvent",
                        ),
                        (
                            "api_projector",
                            "lib.vdm.vdll_api_membership.project_vdll_api",
                        ),
                        (
                            "runtime_name_type",
                            "lib.vdm.vdll_fire_event.ResolvedEventName",
                        ),
                        (
                            "name_projector",
                            "lib.vdm.vdll_fire_event.project_fire_event_recipe",
                        ),
                        (
                            "name_projection_type",
                            "lib.vdm.vdll_fire_event.FireEventRecipe",
                        ),
                        ("event_data_type", "lib.vdm.vdll_fire_event.FireEventData"),
                        ("resolver", "lib.vdm.vdll_fire_event.resolve_fire_event"),
                        ("host_type", "lib.vdm.vdll_api_membership.VdllApiHost"),
                        ("map_type", "lib.vdm.vdll_fire_event.FireEventMapSnapshot"),
                        ("map_entry_type", "lib.vdm.vdll_fire_event.FireEventMapEntry"),
                        (
                            "map_lookup",
                            "lib.vdm.vdll_fire_event.FireEventMapSnapshot.lookup",
                        ),
                        (
                            "parameter_requests",
                            "lib.vdm.vdll_fire_event.fire_event_parameter_requests",
                        ),
                        (
                            "parameter_outcome_type",
                            "lib.vdm.vdll_fire_event.FireEventParamOutcome",
                        ),
                        (
                            "attribute_projector",
                            "lib.vdm.vdll_fire_event.project_fire_event_attribute",
                        ),
                        (
                            "index0_numeric_projector",
                            "lib.vdm.vdll_fire_event.project_fire_event_index0_parameter",
                        ),
                        (
                            "state_error_type",
                            "lib.vdm.vdll_fire_event.UnsupportedFireEvent",
                        ),
                        (
                            "lazy_order",
                            "NULLdata/disabledhost/getterNULL skip before API reads; name bytes parsed only after a nonzero resolved export",
                        ),
                        (
                            "runtime_maps",
                            "explicit active epoch and successful insertion order; first wins per pre/post,host,normalizedVA; query rawVA is not bit-cleared",
                        ),
                        (
                            "consumer",
                            "event DWORD stored, low16 sent to attribute; both parameter-request gates test param1_type; confirmed failures supply empty CString, unknown outcomes are unsupported",
                        ),
                        (
                            "numeric_scope",
                            "index0 pre returnsfalse; post reads supplied u32reg50 before type; numeric3..10 projected, unknown type false only after read; gueststrings/indexN remain external",
                        ),
                        (
                            "unknown",
                            "actual RecID/getter binding, real VDLL namespace, publication/epoch/shadow state, allocation/exception, guest memory/strings/CRT and __siga_check/whole policy",
                        ),
                    )
                ),
            ),
        )
    )


def _export_fire_event(parsed: NdatPayload) -> ArtifactExport:
    model = project_ndat_fire_event(parsed)
    return ArtifactExport(
        "ready",
        (
            Artifact("vdll-fire-event-data.bin", "binary", model.counted_data),
            Artifact(
                "vdll-fire-event-metadata.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_fire_event_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatVdllApi(ValueError):
    """The raw NDAT record is not callback3 VDLL API metadata."""


@dataclass(frozen=True, slots=True)
class NdatVdllApi:
    """Copied module/selector bytes, without guessed runtime VDLL bindings."""

    raw: bytes
    counted_data: bytes
    projection: VdllApiProjection
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


def project_ndat_vdll_api(parsed: NdatPayload) -> NdatVdllApi:
    """Reparse callback3 raw bytes; ordinary copy skips remain metadata."""
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 3:
        raise UnsupportedNdatVdllApi("requires callback decimal3 (0x03)")
    return NdatVdllApi(
        parsed.raw,
        parsed.data_raw,
        project_vdll_api(parsed.data_raw, parsed.data_length),
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _vdll_api_manifest(parsed: NdatPayload) -> JSONObject:
    model = project_ndat_vdll_api(parsed)
    p = model.projection
    ordinal = p.ordinal
    return JSONObject(
        (
            ("format", "vdm.ndat.vdll-api-membership-metadata.v1"),
            ("kind", "engine_vdll_api_membership_metadata_not_ioc"),
            ("counted_data_hex", model.counted_data.hex()),
            ("delimiter_offset", p.delimiter_offset),
            ("skip_reason", p.skip_reason),
            ("module_raw_hex", None if p.module_name is None else p.module_name.hex()),
            ("selector_raw_hex", None if p.selector is None else p.selector.hex()),
            ("selector_copy_hresult", p.selector_copy_hresult),
            ("route", p.route),
            ("name_crc_u32", p.name_crc),
            (
                "ordinal",
                None
                if ordinal is None
                else JSONObject(
                    (
                        ("value_u32", ordinal.value),
                        ("hresult", ordinal.hresult),
                        ("end_offset", ordinal.end_offset),
                    )
                ),
            ),
            (
                "record_name_raw_hex",
                None
                if model.record_id_suffix_raw is None
                else model.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", model.trailing_raw.hex()),
            ("last_nul_required", False),
            ("runtime_recid_used_by_callback", False),
            ("callback_return", None),
            ("registration_completed", None),
            ("record_local_match", None),
            ("final_verdict", None),
            (
                "recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.types.ndat.project_ndat_vdll_api"),
                        ("model_type", "lib.vdm.types.ndat.NdatVdllApi"),
                        (
                            "unsupported_type",
                            "lib.vdm.types.ndat.UnsupportedNdatVdllApi",
                        ),
                        (
                            "pair_projector",
                            "lib.vdm.vdll_api_membership.project_vdll_api",
                        ),
                        (
                            "projection_type",
                            "lib.vdm.vdll_api_membership.VdllApiProjection",
                        ),
                        (
                            "ordinal_parser",
                            "lib.vdm.vdll_api_membership.parse_vdll_ordinal",
                        ),
                        ("ordinal_type", "lib.vdm.vdll_api_membership.VdllOrdinal"),
                        ("crc", "lib.vdm.vdll_api_membership.vdll_api_crc"),
                        ("resolver", "lib.vdm.vdll_api_membership.resolve_vdll_api"),
                        ("host_type", "lib.vdm.vdll_api_membership.VdllApiHost"),
                        (
                            "module_selection_type",
                            "lib.vdm.vdll_api_membership.VdllModuleSelection",
                        ),
                        (
                            "export_table_type",
                            "lib.vdm.vdll_api_membership.VdllExportTable",
                        ),
                        (
                            "named_export_type",
                            "lib.vdm.vdll_api_membership.VdllNamedExport",
                        ),
                        (
                            "resolution_type",
                            "lib.vdm.vdll_api_membership.VdllApiResolution",
                        ),
                        (
                            "membership_type",
                            "lib.vdm.vdll_api_membership.VdllApiMembershipSnapshot",
                        ),
                        (
                            "membership_query",
                            "lib.vdm.vdll_api_membership.VdllApiMembershipSnapshot.contains",
                        ),
                        ("bucket", "lib.vdm.vdll_api_membership.vdll_api_bucket"),
                        (
                            "state_error_type",
                            "lib.vdm.vdll_api_membership.UnsupportedVdllApi",
                        ),
                        (
                            "copy",
                            "counted first ! at1..127; first-NUL copy128; truncation/error HRESULT ignored by native callback",
                        ),
                        (
                            "selector",
                            "named CRC_1 excludesNUL, no uppercase; @ ordinal uses C-locale Windows ULONG32 base0, failed parse still looks up0",
                        ),
                        (
                            "bindings",
                            "four explicit host gates and selected VDLL tables; unknown selection differs from confirmed index miss and valid index0; no OS resolver",
                        ),
                        (
                            "membership",
                            "resolved nonzero VA then host2 clearsbit0, including stored0; actual16x4 bucket vectors and raw queryVA, linear unsorted equality",
                        ),
                        (
                            "runtime_state",
                            "active loaded tables/epoch and membership vectors required; wire order does not establish global state or successful append",
                        ),
                        (
                            "effect",
                            "selected x64 trust branch statically bypasses two counter increments/API-limit when membership true; not whole trust policy, allowlist or final verdict",
                        ),
                        (
                            "native_scope",
                            "explicit fake VDLL tables and module-index service; original copy/CRC/ordinal/export lookup/membership; separate raw CRC1225 and parser80 oracles",
                        ),
                        (
                            "unknown",
                            "real module resolver, runtime bindings/epoch/other writers, realloc/exception partial state and complete trust-switch policy",
                        ),
                    )
                ),
            ),
        )
    )


def _export_vdll_api(parsed: NdatPayload) -> ArtifactExport:
    model = project_ndat_vdll_api(parsed)
    return ArtifactExport(
        "ready",
        (
            Artifact("vdll-api-data.bin", "binary", model.counted_data),
            Artifact(
                "vdll-api-membership.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_vdll_api_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatVfsLink(ValueError):
    """The NDAT record is not callback6 VFS linkage metadata."""


@dataclass(frozen=True, slots=True)
class NdatVfsLink:
    """Raw-authoritative linkage projection, not a completed map insertion."""

    raw: bytes
    counted_data: bytes
    projection: VfsLinkProjection
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes


def project_ndat_vfs_link(parsed: NdatPayload) -> NdatVfsLink:
    """Reparse callback6; unlike pattern callbacks, no last-NUL gate applies."""
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 6:
        raise UnsupportedNdatVfsLink("requires callback decimal6 (0x06)")
    return NdatVfsLink(
        parsed.raw,
        parsed.data_raw,
        project_vfs_link(parsed.data_raw, parsed.data_length),
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _vfs_link_manifest(parsed: NdatPayload) -> JSONObject:
    link = project_ndat_vfs_link(parsed)
    p = link.projection
    return JSONObject(
        (
            ("format", "vdm.ndat.vfs-link-metadata.v1"),
            ("kind", "engine_vfs_linkage_metadata_not_ioc"),
            ("counted_data_hex", link.counted_data.hex()),
            ("delimiter_offset", p.delimiter_offset),
            ("registration_eligible", p.registration_eligible),
            ("skip_reason", p.skip_reason),
            (
                "source_wchar_cstring_hex",
                None if p.source_cstring is None else p.source_cstring.hex(),
            ),
            (
                "target_wchar_cstring_hex",
                None if p.target_cstring is None else p.target_cstring.hex(),
            ),
            ("crc_key_u32", p.source_key),
            (
                "record_name_raw_hex",
                None
                if link.record_id_suffix_raw is None
                else link.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", link.trailing_raw.hex()),
            ("last_nul_required", False),
            ("runtime_recid_used_by_callback", False),
            ("callback_return", None),
            ("map_insertion_completed", None),
            ("record_local_match", None),
            ("final_verdict", None),
            (
                "recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.types.ndat.project_ndat_vfs_link"),
                        ("model_type", "lib.vdm.types.ndat.NdatVfsLink"),
                        (
                            "unsupported_type",
                            "lib.vdm.types.ndat.UnsupportedNdatVfsLink",
                        ),
                        ("pair_projector", "lib.vdm.vfs_link.project_vfs_link"),
                        ("projection_type", "lib.vdm.vfs_link.VfsLinkProjection"),
                        ("crc_callable", "lib.vdm.vfs_link.crc_upper_string_w"),
                        ("snapshot_type", "lib.vdm.vfs_link.VfsRedirectSnapshot"),
                        ("entry_type", "lib.vdm.vfs_link.VfsRedirectEntry"),
                        ("lookup", "lib.vdm.vfs_link.VfsRedirectSnapshot.lookup"),
                        ("state_error_type", "lib.vdm.vfs_link.UnsupportedVfsLink"),
                        (
                            "copy",
                            "first counted >; bounded first-NUL copies; signed byte-to-WCHAR; no unescape/normalization",
                        ),
                        (
                            "crc",
                            "CRCUpperStringW seedFFFFFFFF, ASCII00xx a-z uppercase, low/high bytes, no final XOR",
                        ),
                        (
                            "runtime_order",
                            "explicit successful runtime insertion order and active initial state required; wire arrival is not established runtime order",
                        ),
                        (
                            "lookup_identity",
                            "CRC DWORD only, first key wins; non-NULL empty target is distinct from miss",
                        ),
                        (
                            "query",
                            "actual selected WCHAR CString; VFS normalization/current directory/existence services external",
                        ),
                        (
                            "native_scope",
                            "original callback/map/CRC/lookup with owned object-store services; not full object storage or whole linked-exists chain",
                        ),
                        (
                            "unknown",
                            "allocation/exception partial state, reset/epoch/alias writers, complete VFS and final disposition",
                        ),
                    )
                ),
            ),
        )
    )


def _export_vfs_link(parsed: NdatPayload) -> ArtifactExport:
    link = project_ndat_vfs_link(parsed)
    return ArtifactExport(
        "ready",
        (
            Artifact("vfs-link-data.bin", "binary", link.counted_data),
            Artifact(
                "vfs-link-metadata.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_vfs_link_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatHttpUrlPattern(ValueError):
    """The record is outside the non-null callback-15 pattern framing profile."""


@dataclass(frozen=True, slots=True)
class NdatHttpUrlPattern:
    """Byte pattern input for the engine Boost backend, not a portable regex."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x500000


def project_ndat_http_url_pattern(parsed: NdatPayload) -> NdatHttpUrlPattern:
    """Project decimal callback 15 (0x0F), reparsing authoritative wire bytes.

    Only nonempty counted data ending in NUL is accepted by this projector.
    The constructor reads through the first NUL; later counted bytes still
    participate in the callback's final-byte check. Framing does not establish
    that an arbitrary pattern compiles or matches. No regex engine is invoked.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 15:
        raise UnsupportedNdatHttpUrlPattern("requires callback decimal 15 (0x0F)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatHttpUrlPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatHttpUrlPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _http_url_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_http_url_pattern(parsed)
    except UnsupportedNdatHttpUrlPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.http-url.boost-pattern.v1"),
            ("callback_decimal", 15),
            ("callback_hex", "0x0F"),
            ("framing_supported", True),
            ("raw_hex", pattern.raw.hex()),
            ("counted_data_length", len(pattern.counted_data)),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("first_nul_offset", len(pattern.effective_pattern)),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", pattern.syntax_flags),
            ("syntax_flags_hex", "0x500000"),
            (
                "backend",
                "engine Boost regex; boost::re_detail_500; narrow char w32_regex_traits<char>",
            ),
            (
                "grammar_dispatch",
                "raw flags low two bits 0 select parse_extended; no portable grammar equivalence claimed",
            ),
            (
                "locale_dependency",
                "GetUserDefaultLCID at traits construction; cached LCID-dependent w32 narrow-byte traits",
            ),
            ("traits_internal_lcid", None),
            (
                "subject",
                "Original input+8 URI WCHAR CString converted by CP_UTF8/flags0 through first WCHAR NUL; upstream canonicalization unknown",
            ),
            (
                "query",
                "RegExState::Match CString through first byte NUL -> perl_matcher::find_imp; backend search, not fullmatch",
            ),
            (
                "post_match",
                "RegExStringMatch separately invokes ProcessMatchedSignature with runtime RecID/SigSeq; outer policy not evaluated",
            ),
            ("runtime_record_id", None),
            ("runtime_sigseq", None),
            (
                "record_id_source",
                "loader createrecid/createrecidz, separate from counted pattern bytes",
            ),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_http_url_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatHttpUrlPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatHttpUrlPattern"),
            ("evaluator", None),
            (
                "validation_scope",
                "Pinned DLL host compiled frozen corpus 226 patterns and completed 686 queries; not arbitrary-pattern compile validity, full URI caller execution or portable regex conformance",
            ),
        )
    )


class UnsupportedNdatGenericRegexPattern(ValueError):
    """The record is outside callback-13 non-null pattern registration."""


@dataclass(frozen=True, slots=True)
class NdatGenericRegexPattern:
    """Narrow byte pattern input for generic NDAT's original Boost backend."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x400000


def project_ndat_generic_regex_pattern(parsed: NdatPayload) -> NdatGenericRegexPattern:
    """Reparse callback decimal 13 (0x0D) without decoding its pattern bytes.

    The non-null registration profile requires nonempty counted data ending in
    NUL. Effective bytes before the first NUL include any leading 04 and exclude
    that terminator; counted bytes after it are retained separately. This does not validate regex
    compilation, identify the bytes' business domain, or evaluate a Lua query.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 13:
        raise UnsupportedNdatGenericRegexPattern("requires callback decimal 13 (0x0D)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatGenericRegexPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatGenericRegexPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _generic_regex_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_generic_regex_pattern(parsed)
    except UnsupportedNdatGenericRegexPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.generic-regex.boost-pattern.v1"),
            ("callback_decimal", 13),
            ("callback_hex", "0x0D"),
            ("framing_supported", True),
            ("raw_hex", pattern.raw.hex()),
            ("counted_data_length", len(pattern.counted_data)),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("first_nul_offset", len(pattern.effective_pattern)),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", pattern.syntax_flags),
            ("syntax_flags_hex", "0x400000"),
            (
                "backend",
                "engine Boost regex; boost::re_detail_500; narrow char w32_regex_traits<char>",
            ),
            (
                "grammar_dispatch",
                "raw flags low two bits 0 select parse_extended; bit20 is clear; no portable grammar equivalence claimed",
            ),
            (
                "locale_dependency",
                "GetUserDefaultLCID at traits construction; cached LCID-dependent w32 narrow-byte traits",
            ),
            ("traits_internal_lcid", None),
            (
                "subject",
                "Lua argument 2 result of luaL_checklstring(length_out=NULL), passed as a byte CString through first NUL; caller encoding, coercion and upstream normalization unknown",
            ),
            (
                "query",
                "LsaMpCommonLib::NdatRegExpMatch checks selector low32 == 13; RegExState::Match -> perl_matcher::find_imp searches each row until the first match",
            ),
            (
                "runtime_order",
                "Actual postcallback-ingested vector order required; NdatCmp orders callback/length/full counted bytes ascending then threat ID descending; wire arrival or a stable host sort is not a winner oracle",
            ),
            (
                "post_match",
                "First matched row's runtime RecID -> namefromrecid -> UnpackVirusName; success returns Lua true/name/RecID, miss returns only false; namespace/unpack failures are Lua errors",
            ),
            ("runtime_record_id", None),
            ("runtime_name", None),
            (
                "record_id_source",
                "loader createrecid/createrecidz, separate from counted pattern bytes; row stride24 stores RecID but no SigSeq",
            ),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_generic_regex_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatGenericRegexPattern"),
            (
                "unsupported_error",
                "lib.vdm.types.ndat.UnsupportedNdatGenericRegexPattern",
            ),
            ("evaluator", None),
            (
                "validation_scope",
                "Pinned DLL host compiled frozen corpus 82 raw patterns and completed 410 queries, 102 true; not arbitrary compile validity, Lua/namespace end-to-end execution or portable regex conformance",
            ),
        )
    )


def _export_generic_regex_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_generic_regex_pattern(parsed)
    except UnsupportedNdatGenericRegexPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    manifest = dict(_generic_regex_manifest(parsed).items)
    return ArtifactExport(
        "ready",
        (
            Artifact(
                "generic-regex-pattern.boost.bin", "binary", pattern.effective_pattern
            ),
            Artifact(
                "generic-regex-pattern.json",
                "json",
                json.dumps(manifest, ensure_ascii=True, indent=2).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatSslCertPattern(ValueError):
    """The record is outside callback-18 non-null pattern registration."""


@dataclass(frozen=True, slots=True)
class NdatSslCertPattern:
    """Original Boost pattern bytes for formatted certificate subjects."""

    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x500000


def project_ndat_ssl_cert_pattern(parsed: NdatPayload) -> NdatSslCertPattern:
    """Reparse decimal callback 18 (0x12), preserving arbitrary pattern bytes.

    Nonempty counted data ending in NUL defines this non-null registration
    profile. The effective pattern excludes its first NUL; later counted bytes
    and the independent record-ID suffix/trailing bytes remain separate.
    No certificate parse, regex compilation or query occurs here.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 18:
        raise UnsupportedNdatSslCertPattern("requires callback decimal 18 (0x12)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatSslCertPattern(
            "requires nonempty counted data ending in NUL"
        )
    first_nul = data.index(0)
    return NdatSslCertPattern(
        parsed.raw,
        data,
        data[:first_nul],
        data[first_nul + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _ssl_cert_subject_recipes() -> JSONObject:
    return JSONObject(
        (
            (
                "dn",
                JSONObject(
                    (
                        ("builder", "lib.vdm.ssl_cert_subject.build_ssl_dn_subject"),
                        ("row_type", "lib.vdm.ssl_cert_subject.SslDnStringRow"),
                        (
                            "input",
                            "parsed runtime 24-byte DN rows: type u32 at +0, resolved physical WCHAR CString pointer at +16; not raw DER",
                        ),
                        ("type_order", JSONArray((12, 5, 4, 3, 2, 1, 0))),
                        (
                            "short_labels",
                            JSONArray(("EMAIL", "CN", "OU", "O", "L", "ST", "C")),
                        ),
                        (
                            "selection",
                            "first matching row, including NULL that shadows later duplicates; unknown-type value storage is not selected",
                        ),
                        (
                            "values",
                            "NULL skips; non-NULL empty retains label=; first aligned WCHAR NUL ends each value, later fields still append",
                        ),
                        (
                            "format",
                            "Subject: or Issuer: prefix, then label=value joined by comma-space; no trim or escaping",
                        ),
                        (
                            "caller_roles",
                            "Subject uses certificate+0x40 DN; Issuer uses certificate+0x30 DN",
                        ),
                        (
                            "success_domain",
                            "ASCII selected WCHAR content projected to narrow bytes; non-ASCII/insufficient physical CString storage is typed unsupported, not mismatch",
                        ),
                        (
                            "native_format",
                            "TrNewSprintfA(%s: %ls) -> narrow CRT __stdio_common_vsprintf(locale=NULL); no CP_UTF8 or ACP equivalence claimed",
                        ),
                    )
                ),
            ),
            (
                "validity",
                JSONObject(
                    (
                        (
                            "builder",
                            "lib.vdm.ssl_cert_subject.build_ssl_validity_subject",
                        ),
                        (
                            "snapshot_type",
                            "lib.vdm.ssl_cert_subject.SslValiditySnapshot",
                        ),
                        ("from_words_offset", 88),
                        ("to_words_offset", 104),
                        ("words_per_time", 8),
                        ("used_word_indices", JSONArray((0, 1, 3, 4, 5, 6))),
                        ("offset_dword_offsets", JSONArray((120, 124, 128, 132))),
                        (
                            "gate",
                            "either first year WORD zero supplies no recipe-local subject; original global-pattern-vector gate remains external",
                        ),
                        (
                            "format",
                            "ValidFrom: YYYY-MM-DD hh:mm:ss (UTC + uu:uu) ValidTo: YYYY-MM-DD hh:mm:ss (UTC + uu:uu)",
                        ),
                        (
                            "numeric_rules",
                            "raw unsigned u16/u32, minimum widths 4 for year and 2 otherwise; literal UTC +; no date validation, signed-zone adjustment or current-time test",
                        ),
                    )
                ),
            ),
            ("result_type", "lib.vdm.ssl_cert_subject.SslCertSubject"),
            ("unsupported_error", "lib.vdm.ssl_cert_subject.UnsupportedSslCertSubject"),
            (
                "availability",
                "subject_available is recipe-local only; no regex/NRI/post-match result or complete engine-query eligibility",
            ),
        )
    )


def _ssl_cert_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_ssl_cert_pattern(parsed)
    except UnsupportedNdatSslCertPattern as exc:
        return JSONObject((("framing_supported", False), ("reason", str(exc))))
    return JSONObject(
        (
            ("format", "vdm.ndat.ssl-cert.boost-pattern.v1"),
            ("callback_decimal", 18),
            ("callback_hex", "0x12"),
            ("framing_supported", True),
            ("raw_hex", pattern.raw.hex()),
            ("counted_data_length", len(pattern.counted_data)),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("first_nul_offset", len(pattern.effective_pattern)),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_raw_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", pattern.syntax_flags),
            ("syntax_flags_hex", "0x500000"),
            (
                "backend",
                "engine Boost regex; boost::re_detail_500; narrow char w32_regex_traits<char>",
            ),
            (
                "locale_dependency",
                "runtime GetUserDefaultLCID-dependent regex traits, separate from the narrow CRT DN formatter locale; internal locale values not directly read",
            ),
            ("subject_recipes", _ssl_cert_subject_recipes()),
            (
                "certificate_input",
                "NetworkHipsMatch metadata+0x40 blob view (+4 size/+8 pointer); one BE24 length at bytes3..5 selects bytes+6 for ParsePkcs6Certificate; not a portable ASN.1 or TLS-chain parser",
            ),
            (
                "query",
                "RegExStringMatch -> RegExState::Match/find_imp searches each formatted Subject/Issuer/Validity CString with the original backend",
            ),
            (
                "policy",
                "DN field NRI checks can independently affect builder return; RegExStringMatch invokes ProcessMatchedSignature with runtime RecID/SigSeq; neither is evaluated by these recipes",
            ),
            ("runtime_record_id", None),
            ("runtime_sigseq", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("projector", "lib.vdm.types.ndat.project_ndat_ssl_cert_pattern"),
            ("projection_type", "lib.vdm.types.ndat.NdatSslCertPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatSslCertPattern"),
            ("evaluator", None),
            (
                "validation_scope",
                "278 corpus patterns compiled and 1652 original Match calls completed; formatter/builder evidence is separately scoped, not arbitrary regex validity or full certificate/NRI/scan policy",
            ),
        )
    )


def _export_ssl_cert_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_ssl_cert_pattern(parsed)
    except UnsupportedNdatSslCertPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    return ArtifactExport(
        "ready",
        (
            Artifact("ssl-cert-pattern.boost.bin", "binary", pattern.effective_pattern),
            Artifact(
                "ssl-cert-pattern.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_ssl_cert_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode("utf-8")
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatVbasicPathPattern(ValueError):
    """Outside callback-1 non-NULL pattern-registration framing."""


@dataclass(frozen=True, slots=True)
class NdatVbasicPathPattern:
    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x100000


def project_ndat_vbasic_path_pattern(parsed: NdatPayload) -> NdatVbasicPathPattern:
    """Reparse callback1 and retain raw pattern/count/CString/suffix boundaries.

    This nonempty/last-NUL registration profile does not validate arbitrary
    Boost grammar, infer NULL finalize or decode pattern bytes as Unicode.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 1:
        raise UnsupportedNdatVbasicPathPattern("requires callback decimal1 (0x01)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatVbasicPathPattern(
            "requires nonempty counted data ending in NUL"
        )
    first = data.index(0)
    return NdatVbasicPathPattern(
        parsed.raw,
        data,
        data[:first],
        data[first + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _vbasic_path_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_vbasic_path_pattern(parsed)
    except UnsupportedNdatVbasicPathPattern as exc:
        return JSONObject(
            (
                ("format", "vdm.ndat.vbasic-path.boost-pattern.v1"),
                ("framing_supported", False),
                ("reason", str(exc)),
            )
        )
    return JSONObject(
        (
            ("format", "vdm.ndat.vbasic-path.boost-pattern.v1"),
            ("framing_supported", True),
            ("callback_decimal", 1),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", 0x100000),
            (
                "backend",
                "original RegExState::PushRegEx -> Boost re_detail_500 w32_regex_traits<char>, flags0x100000; CString Match/icase/captures, not a portable regex evaluator",
            ),
            (
                "locale_dependency",
                "runtime default-LCID byte traits; raw invalidUTF8 pattern bytes are retained, not Unicode-decoded/casefolded; host locale is environment only",
            ),
            (
                "subject_recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.vbasic_path.project_vbasic_path_source"),
                        ("field_type", "lib.vdm.vbasic_path.VbasicPathField"),
                        ("result_type", "lib.vdm.vbasic_path.VbasicPathSource"),
                        (
                            "unsupported_error",
                            "lib.vdm.vbasic_path.UnsupportedVbasicPathSource",
                        ),
                        (
                            "domain",
                            "caller-resolved parser+0xB0 field; Load_VBasicData copies VBProjectInfo+0x2A522B here; no mapping/version/parser initialization gates are run by this recipe",
                        ),
                        ("mapped_projectinfo_offset", 0x2A),
                        ("parser_field_offset", 0xB0),
                        ("declared_field_bytes", 522),
                        ("worker_copy_bytes", 520),
                        ("forced_wchar_nul_index", 259),
                        ("code_page", 65001),
                        ("conversion_flags", 0),
                        ("cch_wide_char", -1),
                        ("output_capacity_bytes", 260),
                        (
                            "conversion",
                            "UTF16LE through first aligned NUL after forcing unit259NUL; invalid surrogates replace; UTF8 with NUL must fit260bytes, no heap retry",
                        ),
                        (
                            "gates",
                            "capacity failure sets worker output[0]=0; success forces output[259]=0; API-success empty is distinct but skips true query; missing520B is typed unsupported",
                        ),
                        (
                            "query",
                            "nonempty UTF8CString true call only: regex_subject excludesNUL; caller_hash_cstring and scan_filepath_length includeNUL; no slash/path normalization",
                        ),
                        (
                            "excluded_recovery",
                            "separate low-byte recovery passes scan_filepath boolfalse and bypasses path/name regex vectors; it is not a fallback/second callback1 subject",
                        ),
                        (
                            "descriptor",
                            JSONObject(
                                (
                                    ("address", "0x181289AA0"),
                                    ("path_vector_offset", 0),
                                    ("name_vector_offset", 8),
                                    ("nid_snid_selector_offset", 16),
                                    ("nid_snid_selector", 11),
                                    ("nid_snid_selector_hex", "0x0B"),
                                )
                            ),
                        ),
                        (
                            "boundary",
                            "recipe-local conversion/source availability only; original Win32/engine resource failures, mapper/VBversion/p-code initialization, global patterns, NID/SNID/attributes/basename and ShouldContinueScanning remain external",
                        ),
                    )
                ),
            ),
            (
                "query",
                "original full converted path CString to Match/find_imp; row RecID and post-match ShouldContinueScanning/delayed reporting are not final verdicts",
            ),
            ("projector", "lib.vdm.types.ndat.project_ndat_vbasic_path_pattern"),
            ("pattern_type", "lib.vdm.types.ndat.NdatVbasicPathPattern"),
            (
                "unsupported_error",
                "lib.vdm.types.ndat.UnsupportedNdatVbasicPathPattern",
            ),
            ("runtime_record_id", None),
            ("runtime_name", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("evaluator", None),
            ("portable_projection", None),
        )
    )


def _export_vbasic_path_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_vbasic_path_pattern(parsed)
    except UnsupportedNdatVbasicPathPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    return ArtifactExport(
        "ready",
        (
            Artifact(
                "vbasic-path-pattern.boost.bin", "binary", pattern.effective_pattern
            ),
            Artifact(
                "vbasic-path-pattern.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_vbasic_path_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode()
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatPdbPathPattern(ValueError):
    """Outside callback-10 non-NULL pattern-registration framing."""


@dataclass(frozen=True, slots=True)
class NdatPdbPathPattern:
    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    syntax_flags: int = 0x100000


def project_ndat_pdb_path_pattern(parsed: NdatPayload) -> NdatPdbPathPattern:
    """Reparse callback10, preserving byte spelling and first-NUL boundaries.

    Nonempty counted data ending in NUL is the non-NULL registration profile,
    not arbitrary Boost compilation validation or a wire NULL-finalize rule.
    No path normalization, decoding, portable regex or policy evaluation runs.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 10:
        raise UnsupportedNdatPdbPathPattern("requires callback decimal10 (0x0A)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatPdbPathPattern(
            "requires nonempty counted data ending in NUL"
        )
    first = data.index(0)
    return NdatPdbPathPattern(
        parsed.raw,
        data,
        data[:first],
        data[first + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
    )


def _pdb_path_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_pdb_path_pattern(parsed)
    except UnsupportedNdatPdbPathPattern as exc:
        return JSONObject(
            (
                ("format", "vdm.ndat.pdb-path.boost-pattern.v1"),
                ("framing_supported", False),
                ("reason", str(exc)),
            )
        )
    return JSONObject(
        (
            ("format", "vdm.ndat.pdb-path.boost-pattern.v1"),
            ("framing_supported", True),
            ("callback_decimal", 10),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", 0x100000),
            (
                "backend",
                "original RegExState::PushRegEx -> Boost re_detail_500 w32_regex_traits<char>, raw flags0x100000; native ASCII icase/capture-backreference controls, not portable regex equivalence",
            ),
            (
                "locale_dependency",
                "runtime default-LCID byte traits; UTF8 wire spelling does not imply Unicode decoding/casefold; host LCID/ACP is environment, not internal traits readback",
            ),
            (
                "subject_recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.pdb_path.project_pdb_path_source"),
                        ("snapshot_type", "lib.vdm.pdb_path.PdbDebugSnapshot"),
                        ("mapping_type", "lib.vdm.pdb_path.PdbMappedBytes"),
                        ("result_type", "lib.vdm.pdb_path.PdbPathSource"),
                        (
                            "unsupported_error",
                            "lib.vdm.pdb_path.UnsupportedPdbPathSource",
                        ),
                        (
                            "input",
                            "resolved pecontext directory u32 fields+20F4/+20F8 and mapped base u64+83798; caller-supplied mapped stages, not disk file offsets or a PE mapper",
                        ),
                        (
                            "selection",
                            "first28-byte debug entry only: Type+12==2, AddressOfRawData+20 nonzero, SizeOfData+16>=25; map24-byte header and require RSDS",
                        ),
                        (
                            "path",
                            "CodeView+24 mapped CString; original mmap_string_ex maximum=SizeOfData-23, out length excludes NUL, empty skips; no added terminator or multi-entry/NB10 fallback",
                        ),
                        (
                            "mapping_boundary",
                            "missing stages/insufficient physical data/wrong addresses are typed unsupported; explicit mapping failure and normal gates remain distinct; successful resolved storage does not reconstruct mapping-window/cache/remap history",
                        ),
                        (
                            "address_arithmetic",
                            "zero-extended u32 fields plus mapped base modulo u64; maximum subtraction is original u32 SizeOfData-23 after >=25 gate",
                        ),
                        (
                            "subject",
                            "original full mapped path byte CString, not basename or process path; no caller Unicode/UTF8 conversion, slash rewriting or path virtualization in the regex loop",
                        ),
                        (
                            "descriptor",
                            JSONObject(
                                (
                                    ("address", "0x181289AB8"),
                                    ("path_vector_offset", 0),
                                    ("name_vector_offset", 8),
                                    ("nid_snid_selector_offset", 16),
                                    ("nid_snid_selector", 77),
                                    ("nid_snid_selector_hex", "0x4D"),
                                )
                            ),
                        ),
                        (
                            "boundary",
                            "recipe-local source only; attributes/NID/SNID/basename processing can change execution, and ShouldContinueScanning/delayed reporting remain external",
                        ),
                    )
                ),
            ),
            (
                "query",
                "RegExState::Match searches byte CString through its first NUL with original find_imp; regex hit passes row RecID to ShouldContinueScanning(result1,sequence0,EmptySha1), not final disposition",
            ),
            ("projector", "lib.vdm.types.ndat.project_ndat_pdb_path_pattern"),
            ("pattern_type", "lib.vdm.types.ndat.NdatPdbPathPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatPdbPathPattern"),
            ("runtime_record_id", None),
            ("runtime_name", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
            ("evaluator", None),
            ("portable_projection", None),
        )
    )


def _export_pdb_path_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_pdb_path_pattern(parsed)
    except UnsupportedNdatPdbPathPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    return ArtifactExport(
        "ready",
        (
            Artifact("pdb-path-pattern.boost.bin", "binary", pattern.effective_pattern),
            Artifact(
                "pdb-path-pattern.json",
                "json",
                json.dumps(
                    semantic_json_to_data(_pdb_path_manifest(parsed)),
                    ensure_ascii=True,
                    indent=2,
                ).encode()
                + b"\n",
            ),
        ),
    )


class UnsupportedNdatRawBodyPattern(ValueError):
    """Outside callback-19 non-NULL pattern-registration framing."""


@dataclass(frozen=True, slots=True)
class NdatRawBodyPattern:
    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    portable_pattern: RawBodyPattern | None
    portable_reason: str | None
    syntax_flags: int = 0x400000


def project_ndat_raw_body_pattern(parsed: NdatPayload) -> NdatRawBodyPattern:
    """Reparse callback19 and preserve backend bytes beyond portable grammar.

    Nonempty counted data ending in NUL is a non-NULL registration profile;
    effective bytes exclude the first NUL, with remaining counted bytes and
    suffix/trailing separate. Framing never asserts arbitrary compile validity.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 19:
        raise UnsupportedNdatRawBodyPattern("requires callback decimal19 (0x13)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatRawBodyPattern(
            "requires nonempty counted data ending in NUL"
        )
    first = data.index(0)
    effective = data[:first]
    try:
        portable, reason = compile_raw_body_pattern(effective), None
    except UnsupportedRawBodyPattern as exc:
        portable, reason = None, str(exc)
    return NdatRawBodyPattern(
        parsed.raw,
        data,
        effective,
        data[first + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
        portable,
        reason,
    )


def _raw_body_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_raw_body_pattern(parsed)
    except UnsupportedNdatRawBodyPattern as exc:
        return JSONObject(
            (
                ("format", "vdm.ndat.raw-body.boost-pattern.v1"),
                ("framing_supported", False),
                ("reason", str(exc)),
            )
        )
    portable = pattern.portable_pattern
    rule_name = (
        "ndat_raw_body_" + hashlib.sha256(pattern.raw).hexdigest()
        if portable is not None
        else None
    )
    return JSONObject(
        (
            ("format", "vdm.ndat.raw-body.boost-pattern.v1"),
            ("framing_supported", True),
            ("callback_decimal", 19),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", 0x400000),
            ("search_match_flags_u32", 0x400),
            (
                "backend",
                "original Boost re_detail_500 w32 byte traits; binary iterator Search, not CString subject or BM",
            ),
            (
                "locale_dependency",
                "original runtime default-LCID traits; host locale observations are environment, not internal traits readback",
            ),
            (
                "subject_recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.raw_body.project_raw_body_queries"),
                        ("view_type", "lib.vdm.raw_body.RawBodyView"),
                        ("query_type", "lib.vdm.raw_body.RawBodyQuery"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_body.UnsupportedRawBodySubject",
                        ),
                        ("ordered_metadata_offsets", JSONArray((0x30, 0x38))),
                        ("ordered_policy_bytes", JSONArray((0, 1))),
                        (
                            "range",
                            "each independent view: full buffer pointer+8, zero-extended u32 size+4; NULL view/buffer or zero size skips only that view",
                        ),
                        (
                            "boundary",
                            "no SSL+6/BE24 framing, concatenation or inferred HTTP request/response/decoding; pattern-vector presence and runtime policy remain external",
                        ),
                    )
                ),
            ),
            (
                "portable_projection",
                JSONObject(
                    (
                        ("supported", portable is not None),
                        ("reason", pattern.portable_reason),
                        (
                            "language",
                            "strict printable ASCII/hex/escaped-punctuation bytes, dot-any256, top-level alternatives, CC{1,8}, internal .{32}/.{0,8} jumps only; nonnullable branches",
                        ),
                        (
                            "anchors",
                            "only fixed literal branches excluding boundary bytes; previous/next 0A/0C/0D/85 or selected-span bounds; not general regex anchors",
                        ),
                        (
                            "branches",
                            None
                            if portable is None
                            else JSONArray(
                                tuple(
                                    JSONObject(
                                        (
                                            ("start_anchor", branch.start_anchor),
                                            ("end_anchor", branch.end_anchor),
                                            (
                                                "tokens",
                                                JSONArray(
                                                    tuple(
                                                        JSONObject(
                                                            (
                                                                ("value", token.value),
                                                                (
                                                                    "minimum",
                                                                    token.minimum,
                                                                ),
                                                                (
                                                                    "maximum",
                                                                    token.maximum,
                                                                ),
                                                            )
                                                        )
                                                        for token in branch.tokens
                                                    )
                                                ),
                                            ),
                                        )
                                    )
                                    for branch in portable.branches
                                )
                            ),
                        ),
                        ("compiler", "lib.vdm.raw_body.compile_raw_body_pattern"),
                        ("pattern_type", "lib.vdm.raw_body.RawBodyPattern"),
                        ("branch_type", "lib.vdm.raw_body.RawBodyBranch"),
                        ("token_type", "lib.vdm.raw_body.RawBodyToken"),
                        ("predicate", "lib.vdm.raw_body.search_raw_body_bytes"),
                        ("renderer", "lib.vdm.raw_body.render_raw_body_yara"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_body.UnsupportedRawBodyPattern",
                        ),
                        ("rule_name", rule_name),
                        (
                            "yara_source",
                            None
                            if portable is None
                            else render_raw_body_yara(portable, rule_name),
                        ),
                        (
                            "scope",
                            "Boolean search/YARA only on identical explicit selected subject bytes; no native resource/exception or post-match policy model",
                        ),
                        (
                            "validated_yara_version",
                            "4.5.4 frozen corpus/recorded-span differential",
                        ),
                        ("yara_compile_valid", None),
                    )
                ),
            ),
            ("projector", "lib.vdm.types.ndat.project_ndat_raw_body_pattern"),
            ("pattern_type", "lib.vdm.types.ndat.NdatRawBodyPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatRawBodyPattern"),
            (
                "query",
                "all rows Search then ProcessMatchedSignature consumes runtime RecID/SigSeq/context/metadata and per-view0/1 policy; regex hit is not final policy success",
            ),
            ("runtime_record_id", None),
            ("runtime_signature_sequence", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
        )
    )


def _export_raw_body_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_raw_body_pattern(parsed)
    except UnsupportedNdatRawBodyPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    manifest = _raw_body_manifest(parsed)
    artifacts = [
        Artifact("raw-body-pattern.boost.bin", "binary", pattern.effective_pattern),
        Artifact(
            "raw-body-pattern.json",
            "json",
            json.dumps(
                semantic_json_to_data(manifest), ensure_ascii=True, indent=2
            ).encode()
            + b"\n",
        ),
    ]
    if pattern.portable_pattern is not None:
        name = "ndat_raw_body_" + hashlib.sha256(pattern.raw).hexdigest()
        artifacts.append(
            Artifact(
                "raw-body-pattern.yar",
                "yara",
                (
                    "// Same selected explicit body-view span only; no network policy or HTTP-role inference.\n"
                    + render_raw_body_yara(pattern.portable_pattern, name)
                ).encode("ascii"),
            )
        )
    return ArtifactExport("ready", tuple(artifacts))


class UnsupportedNdatRawSslPattern(ValueError):
    """Outside callback-20 non-NULL pattern-registration framing."""


@dataclass(frozen=True, slots=True)
class NdatRawSslPattern:
    raw: bytes
    counted_data: bytes
    effective_pattern: bytes
    after_pattern_terminator: bytes
    record_id_suffix_raw: bytes | None
    trailing_raw: bytes
    portable_pattern: RawSslBytePattern | None
    portable_reason: str | None
    syntax_flags: int = 0x400000


def project_ndat_raw_ssl_pattern(parsed: NdatPayload) -> NdatRawSslPattern:
    """Reparse callback20; preserve Boost bytes even outside portable grammar.

    Nonempty counted data must end in NUL. Constructor input excludes its first
    NUL, with later counted bytes preserved separately from suffix/trailing.
    This framing is not compile validation or a NULL-finalize classification.
    """
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index != 20:
        raise UnsupportedNdatRawSslPattern("requires callback decimal 20 (0x14)")
    data = parsed.data_raw
    if not data or data[-1] != 0:
        raise UnsupportedNdatRawSslPattern(
            "requires nonempty counted data ending in NUL"
        )
    first = data.index(0)
    effective = data[:first]
    try:
        portable = compile_raw_ssl_byte_pattern(effective)
        reason = None
    except UnsupportedRawSslPattern as exc:
        portable, reason = None, str(exc)
    return NdatRawSslPattern(
        parsed.raw,
        data,
        effective,
        data[first + 1 :],
        parsed.record_id_suffix_raw,
        parsed.trailing_raw,
        portable,
        reason,
    )


def _raw_ssl_manifest(parsed: NdatPayload) -> JSONObject:
    try:
        pattern = project_ndat_raw_ssl_pattern(parsed)
    except UnsupportedNdatRawSslPattern as exc:
        return JSONObject(
            (
                ("format", "vdm.ndat.raw-ssl-cert.boost-pattern.v1"),
                ("framing_supported", False),
                ("reason", str(exc)),
            )
        )
    portable = pattern.portable_pattern
    return JSONObject(
        (
            ("format", "vdm.ndat.raw-ssl-cert.boost-pattern.v1"),
            ("framing_supported", True),
            ("callback_decimal", 20),
            ("counted_data_hex", pattern.counted_data.hex()),
            ("effective_pattern_hex", pattern.effective_pattern.hex()),
            ("after_pattern_terminator_hex", pattern.after_pattern_terminator.hex()),
            (
                "record_id_suffix_hex",
                None
                if pattern.record_id_suffix_raw is None
                else pattern.record_id_suffix_raw.hex(),
            ),
            ("trailing_hex", pattern.trailing_raw.hex()),
            ("syntax_flags_u32", 0x400000),
            ("search_match_flags_u32", 0x400),
            (
                "backend",
                "original Boost re_detail_500 w32_regex_traits<char>; unsigned-char iterator regex_search, not BM or CString subject",
            ),
            (
                "locale_dependency",
                "runtime default LCID traits; host LCID/ACP evidence is environment only, not internal traits readback",
            ),
            (
                "subject_recipe",
                JSONObject(
                    (
                        ("projector", "lib.vdm.raw_ssl_cert.project_raw_ssl_subject"),
                        ("view_type", "lib.vdm.raw_ssl_cert.RawSslMetadataView"),
                        ("result_type", "lib.vdm.raw_ssl_cert.RawSslSubject"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_ssl_cert.UnsupportedRawSslSubject",
                        ),
                        (
                            "source",
                            "metadata+0x40 resolved view; u32 size+4, physical buffer pointer+8",
                        ),
                        (
                            "gates",
                            "NULL view/buffer, size<6 or BE24 buffer[3:6]>size-6 skip this local branch; insufficient physical bytes are unsupported",
                        ),
                        (
                            "subject",
                            "buffer[6:size], including declared-certificate suffix bytes and embedded NUL; parser_span=buffer[6:6+BE24] is separate",
                        ),
                        (
                            "boundary",
                            "prefix[0:3] semantics/upstream mapping/global patterns/resources/post-policy are external; no TLS/DER parser",
                        ),
                    )
                ),
            ),
            (
                "portable_projection",
                JSONObject(
                    (
                        ("supported", portable is not None),
                        ("reason", pattern.portable_reason),
                        (
                            "language",
                            "nonempty fixed-width ASCII \\xHH, literal H and [^\\xHH] tokens only; case-sensitive bytes",
                        ),
                        (
                            "atoms",
                            None
                            if portable is None
                            else JSONArray(
                                tuple(
                                    JSONObject(
                                        (("value", a.value), ("negated", a.negated))
                                    )
                                    for a in portable.atoms
                                )
                            ),
                        ),
                        (
                            "yara_rhs",
                            None if portable is None else raw_ssl_yara_rhs(portable),
                        ),
                        (
                            "rule_name",
                            None
                            if portable is None
                            else "ndat_raw_ssl_"
                            + hashlib.sha256(pattern.raw).hexdigest(),
                        ),
                        (
                            "compiler",
                            "lib.vdm.raw_ssl_cert.compile_raw_ssl_byte_pattern",
                        ),
                        ("pattern_type", "lib.vdm.raw_ssl_cert.RawSslBytePattern"),
                        ("atom_type", "lib.vdm.raw_ssl_cert.RawSslByteAtom"),
                        ("predicate", "lib.vdm.raw_ssl_cert.search_raw_ssl_bytes"),
                        ("rhs_exporter", "lib.vdm.raw_ssl_cert.raw_ssl_yara_rhs"),
                        (
                            "unsupported_error",
                            "lib.vdm.raw_ssl_cert.UnsupportedRawSslPattern",
                        ),
                        (
                            "scope",
                            "Boolean predicate/YARA applied only to identical explicit subject slice; not complete Boost grammar or policy",
                        ),
                        ("yara_compile_valid", None),
                        (
                            "yara_minimum_version",
                            "4.3.0"
                            if portable is not None
                            and any(a.negated for a in portable.atoms)
                            else None,
                        ),
                        (
                            "validated_yara_version",
                            "4.5.4 (frozen corpus/recorded-span differential only)",
                        ),
                    )
                ),
            ),
            ("projector", "lib.vdm.types.ndat.project_ndat_raw_ssl_pattern"),
            ("pattern_type", "lib.vdm.types.ndat.NdatRawSslPattern"),
            ("unsupported_error", "lib.vdm.types.ndat.UnsupportedNdatRawSslPattern"),
            (
                "query",
                "RegExBinaryMatch searches every row, then ProcessMatchedSignature consumes runtime RecID/SigSeq/context; regex hit is not policy success",
            ),
            ("runtime_record_id", None),
            ("runtime_signature_sequence", None),
            ("compile_valid", None),
            ("record_local_match", None),
            ("final_verdict", None),
        )
    )


def _export_raw_ssl_pattern(parsed: NdatPayload) -> ArtifactExport:
    try:
        pattern = project_ndat_raw_ssl_pattern(parsed)
    except UnsupportedNdatRawSslPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    artifacts = [
        Artifact("raw-ssl-cert-pattern.boost.bin", "binary", pattern.effective_pattern),
        Artifact(
            "raw-ssl-cert-pattern.json",
            "json",
            json.dumps(
                semantic_json_to_data(_raw_ssl_manifest(parsed)),
                ensure_ascii=True,
                indent=2,
            ).encode()
            + b"\n",
        ),
    ]
    if pattern.portable_pattern is not None:
        rhs = raw_ssl_yara_rhs(pattern.portable_pattern)
        artifacts.append(
            Artifact(
                "raw-ssl-cert-pattern.yar",
                "yara",
                (
                    "// Apply only to the selected explicit raw subject span; no engine policy.\nrule ndat_raw_ssl_"
                    + hashlib.sha256(pattern.raw).hexdigest()
                    + " {\n strings:\n  $a = "
                    + rhs
                    + "\n condition:\n  $a\n}\n"
                ).encode("ascii"),
            )
        )
    return ArtifactExport("ready", tuple(artifacts))


def export_ndat(parsed: NdatPayload) -> ArtifactExport:
    """Export supported NDAT pattern inputs and linkage metadata."""
    parsed = parse_ndat(parsed.raw)
    if parsed.callback_index == 7:
        return _export_api_attribute(parsed)
    if parsed.callback_index == 4:
        return _export_fire_event(parsed)
    if parsed.callback_index == 3:
        return _export_vdll_api(parsed)
    if parsed.callback_index == 6:
        return _export_vfs_link(parsed)
    if parsed.callback_index == 1:
        return _export_vbasic_path_pattern(parsed)
    if parsed.callback_index == 10:
        return _export_pdb_path_pattern(parsed)
    if parsed.callback_index == 19:
        return _export_raw_body_pattern(parsed)
    if parsed.callback_index == 20:
        return _export_raw_ssl_pattern(parsed)
    if parsed.callback_index == 18:
        return _export_ssl_cert_pattern(parsed)
    if parsed.callback_index == 13:
        return _export_generic_regex_pattern(parsed)
    try:
        pattern = project_ndat_http_url_pattern(parsed)
    except UnsupportedNdatHttpUrlPattern as exc:
        return ArtifactExport("unsupported", reason=str(exc))
    manifest = dict(_http_url_manifest(parsed).items)
    return ArtifactExport(
        "ready",
        (
            Artifact("http-url-pattern.boost.bin", "binary", pattern.effective_pattern),
            Artifact(
                "http-url-pattern.json",
                "json",
                json.dumps(manifest, ensure_ascii=True, indent=2).encode("utf-8")
                + b"\n",
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class NdatProcessPrefix:
    """A prefix stage result, not an accepted or matched NDAT rule."""

    suffix_prepared_process: str
    prefix: str
    consumed_utf16_units: int
    process: str
    process_flags: int


def parse_ndat_process_prefix(suffix_prepared_process: str) -> NdatProcessPrefix:
    """Decode a process field after successful GetEFlagsFromPath preparation.

    The caller supplies UTF-16 text content before its terminating NUL, before
    path/environment expansion. Embedded NUL is outside this API's input domain;
    rejecting it does not assert that the engine rejects an equivalent wire blob.
    This helper performs no wire decoding, field splitting, or suffix conversion.
    """
    if "\0" in suffix_prepared_process:
        raise ValueError("prefix stage requires text content without a NUL terminator")
    bits = {">": 1, "<": 2, "!": 4, "?": 8}
    flags = 0
    consumed = 0
    for character in suffix_prepared_process:
        bit = bits.get(character)
        if bit is None:
            break
        flags |= bit
        consumed += 1
    # Every consumed prefix character is one UTF-16 code unit.
    return NdatProcessPrefix(
        suffix_prepared_process,
        suffix_prepared_process[:consumed],
        consumed,
        suffix_prepared_process[consumed:],
        flags,
    )


def evaluate_ndat_stream_gate(
    process_flags: int,
    *,
    stream_present: bool,
    stream_mode: int,
    stream_event: int,
) -> bool:
    """Evaluate only ConfirmMatch's mode/event gate in a valid caller context.

    A true result, including a null-stream bypass, does not establish a rule match.
    Valid PID/context, earlier checks, process comparison and interface effects
    remain the caller's responsibility. Arguments are required unsigned DWORDs;
    no mode/event names or defaults are inferred.
    """
    for name, value in (
        ("process_flags", process_flags),
        ("stream_mode", stream_mode),
        ("stream_event", stream_event),
    ):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"{name} must be an unsigned DWORD")
    if type(stream_present) is not bool:
        raise ValueError("stream_present must be a bool")
    if not stream_present:
        return True
    modes = process_flags & 3
    if modes and not (
        (stream_mode == 0 and modes & 1) or (stream_mode == 1 and modes & 2)
    ):
        return False
    return not process_flags & 8 or stream_event == 5


def _process_stage_contract() -> JSONObject:
    return JSONObject(
        (
            ("field_index", 1),
            ("input_stage", "GetEFlagsFromPath-successful UTF-16 process content"),
            (
                "input_requirement",
                "before terminating NUL and path/environment expansion",
            ),
            ("wire_projection", None),
            ("whole_rule_evaluator", False),
            ("prefix_bits", JSONObject(((">", 1), ("<", 2), ("!", 4), ("?", 8)))),
            ("prefix_consumption", "leading run only; OR repeats; no whitespace trim"),
            ("process_flags_entry_offset", 0x60),
            (
                "stream_gate",
                "null stream bypasses; otherwise mask 0x03 selects mode 0/1 by masks 0x01/0x02 and mask 0x08 requires event 5",
            ),
            (
                "stream_gate_requirement",
                "valid caller/PID context; other checks remain",
            ),
            ("process_dispatch_order", "after the mode/event gate"),
            (
                "process_early_success",
                "first character '*' with any tail, or empty process with PID 4",
            ),
            (
                "early_success_effect",
                "skips interface override and out_record_id write",
            ),
            (
                "mask_0x04_effect",
                "selects ComparePartialProcessName 0x1803CF7C4; not negation",
            ),
            ("without_mask_0x04", "selects CompareIgnoringDeviceVolume 0x1803CF85C"),
            ("interface_effect", "may overwrite the process comparison result"),
        )
    )


def parse_ndat(payload: bytes) -> NdatPayload:
    """Parse the counted data, callback index, and optional record-ID suffix."""
    if len(payload) < 4:
        raise ValueError(
            f"truncated NDAT payload: need 4-byte data length, have {len(payload)}"
        )

    data_length = int.from_bytes(payload[:4], "little")
    callback_offset = 4 + data_length
    if callback_offset >= len(payload):
        available = max(0, len(payload) - 4)
        raise ValueError(
            "truncated NDAT payload: "
            f"declared {data_length} data bytes and callback byte, have {available}"
        )

    suffix_and_trailing = payload[callback_offset + 1 :]
    record_id_suffix_raw: bytes | None = None
    trailing_raw = b""
    if suffix_and_trailing:
        terminator = suffix_and_trailing.find(b"\0")
        if terminator < 0:
            raise ValueError("unterminated NDAT record-ID suffix")
        record_id_suffix_raw = suffix_and_trailing[: terminator + 1]
        trailing_raw = suffix_and_trailing[terminator + 1 :]

    return NdatPayload(
        raw=payload,
        data_length=data_length,
        data_raw=payload[4:callback_offset],
        callback_index=payload[callback_offset],
        record_id_suffix_raw=record_id_suffix_raw,
        trailing_raw=trailing_raw,
    )


def _text_preview(data: bytes) -> str:
    preview = data[:PREVIEW_SIZE]
    text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in preview)
    if len(data) > PREVIEW_SIZE:
        text += "..."
    return text or "(empty)"


def _preview_rows(data: bytes) -> tuple[tuple[str, str], ...]:
    return (
        ("hex_preview", data[:PREVIEW_SIZE].hex(" ") or "(empty)"),
        ("text_preview", _text_preview(data)),
    )


def render_ndat(parsed: NdatPayload) -> FormatResult:
    parsed = parse_ndat(parsed.raw)
    suffix = parsed.record_id_suffix_raw
    rows = [
        ("data_length", f"{parsed.data_length} B"),
        ("callback_index", f"{parsed.callback_index} (0x{parsed.callback_index:02x})"),
        ("record_id_suffix", _text_preview(suffix[:-1]) if suffix else "not present"),
    ]
    if parsed.trailing_raw:
        rows.append(("ignored_trailing_length", f"{len(parsed.trailing_raw)} B"))

    link_rows = ()
    if parsed.callback_index == 6:
        p = project_ndat_vfs_link(parsed).projection
        link_rows = (
            (
                "source",
                repr(p.source_cstring[:-2].decode("utf-16le"))
                if p.source_cstring is not None
                else "not selected",
            ),
            (
                "target",
                repr(p.target_cstring[:-2].decode("utf-16le"))
                if p.target_cstring is not None
                else "not selected",
            ),
            (
                "registration",
                "eligible; runtime insertion external"
                if p.registration_eligible
                else p.skip_reason,
            ),
        )
    api_rows = ()
    if parsed.callback_index == 3:
        p = project_ndat_vdll_api(parsed).projection
        if p.skip_reason is not None:
            api_rows = (("registration", "skip: " + p.skip_reason),)
        else:
            api_rows = (
                ("module!selector", f"{p.module_name!r}!{p.selector!r}"),
                (
                    "selector",
                    f"CRC 0x{p.name_crc:08x}"
                    if p.route == "named"
                    else f"ordinal {p.ordinal.value}; parse HRESULT 0x{p.ordinal.hresult:08x}",
                ),
                (
                    "copy_hresult",
                    f"0x{p.selector_copy_hresult:08x}; runtime binding required",
                ),
            )
    fire_rows = ()
    if parsed.callback_index == 4:
        model = project_ndat_fire_event(parsed)
        api, candidate = model.api_projection, model.name_recipe_candidate
        candidate_text = (
            "absent; runtime name unknown"
            if candidate is None
            else "skip: " + candidate.skip_reason
            if candidate.data is None
            else f"{'post' if candidate.post else 'pre'} event {candidate.data.event_id}; params {candidate.data.param1_index}:{candidate.data.param1_type}, {candidate.data.param2_index}:{candidate.data.param2_type}"
        )
        fire_rows = (
            (
                "module!selector",
                f"{api.module_name!r}!{api.selector!r}"
                if api.skip_reason is None
                else "skip: " + api.skip_reason,
            ),
            ("wire name candidate", model.candidate_issue or candidate_text),
        )
    attribute_rows = ()
    if parsed.callback_index == 7:
        p = project_ndat_api_attribute(parsed).projection
        api = p.api
        attribute_rows = (
            (
                "module!selector",
                "skip: " + api.skip_reason
                if api.skip_reason is not None
                else f"{api.module_name!r}!{api.selector[: p.colon_offset]!r}"
                if p.colon_offset is not None
                else f"{api.module_name!r}!{api.selector!r}; colon missing",
            ),
            (
                "attribute",
                "not selected" if p.attribute_name is None else repr(p.attribute_name),
            ),
        )
    return FormatResult(
        sections=(
            DisplaySection("NDAT Metadata", rows=tuple(rows)),
            DisplaySection("NDAT Data", rows=_preview_rows(parsed.data_raw)),
            *(
                (DisplaySection("VDLL API Attribute", rows=attribute_rows),)
                if attribute_rows
                else ()
            ),
            *((DisplaySection("VFS Link", rows=link_rows),) if link_rows else ()),
            *(
                (DisplaySection("VDLL API Membership", rows=api_rows),)
                if api_rows
                else ()
            ),
            *(
                (DisplaySection("VDLL Event Metadata", rows=fire_rows),)
                if fire_rows
                else ()
            ),
        )
    )


def export_ndat_semantics(parsed: NdatPayload) -> RuleSemantics:
    """Export only NDAT callbacks tied to a static registration and consumer."""
    parsed = parse_ndat(parsed.raw)
    callback_targets = {
        1: "VbasicPathNdatCallback",
        3: "VdllNdatDontCountCallback",
        4: "VdllNdatFireEventCallback",
        5: "LogSkipNdatCallback",
        6: "VdllNdatVfsLinkCallback",
        7: "VdllNdatApiAttributeCallback",
        8: "RkpatCallback",
        10: "PdbPathNdatCallback",
        12: "DnsCacheInfoNdatCallback_0",
        13: "GenericRegExpNdatCallback",
        15: "HttpUrlNdatCallback",
        16: "HttpHeaderNdatCallback",
        17: "MsgBodyNdatCallback",
        18: "SSLCertNdatCallback",
        19: "RawBodyNdatCallback",
        20: "RawSSLCertNdatCallback",
        21: "AsrAutoEnableNdatCallback",
        22: "CAsrNotAllowedNdatCallback",
        23: "McpServersNdatCallback",
    }
    callback_semantics = {
        5: "logskip_rule_ingest",
        22: "custom_asr_not_allowed_rule_ingest",
    }
    callback_target = callback_targets.get(parsed.callback_index)
    has_http_url_consumer = parsed.callback_index == 15
    has_generic_regex_consumer = parsed.callback_index == 13
    has_ssl_cert_consumer = parsed.callback_index == 18
    has_raw_ssl_consumer = parsed.callback_index == 20
    has_raw_body_consumer = parsed.callback_index == 19
    has_pdb_path_consumer = parsed.callback_index == 10
    has_vbasic_path_consumer = parsed.callback_index == 1
    has_vfs_link_consumer = parsed.callback_index == 6
    has_vdll_api_consumer = parsed.callback_index == 3
    has_fire_event_consumer = parsed.callback_index == 4
    has_api_attribute_consumer = parsed.callback_index == 7
    business_semantics = (
        "boost_w32_byte_pattern_ingest_and_uri_search"
        if has_http_url_consumer
        else "boost_w32_byte_pattern_ingest_and_lua_search"
        if has_generic_regex_consumer
        else "boost_w32_pattern_ingest_and_formatted_certificate_search"
        if has_ssl_cert_consumer
        else "boost_w32_binary_pattern_ingest_and_explicit_raw_span_search"
        if has_raw_ssl_consumer
        else "boost_w32_binary_pattern_ingest_and_ordered_raw_views_search"
        if has_raw_body_consumer
        else "boost_w32_pdb_path_pattern_ingest_and_rsds_cstring_search"
        if has_pdb_path_consumer
        else "boost_w32_vbasic_path_pattern_ingest_and_projectinfo_utf8_search"
        if has_vbasic_path_consumer
        else "crc_keyed_vfs_redirect_metadata"
        if has_vfs_link_consumer
        else "vdll_resolved_api_membership_metadata"
        if has_vdll_api_consumer
        else "vdll_runtime_name_event_recipe_metadata"
        if has_fire_event_consumer
        else "vdll_api_attribute_metadata_and_pre_call_aggregation_request"
        if has_api_attribute_consumer
        else callback_semantics.get(parsed.callback_index, "unknown")
    )
    has_logskip_consumer = parsed.callback_index in callback_semantics
    issues = []
    if has_api_attribute_consumer:
        issues.append(
            SemanticIssue(
                "api_attribute_runtime_storage_and_map_required",
                "Raw module!selector:attribute projection does not initialize VDLL tables, establish kstore or borrowed pointer lifetime, or prove map insertion. Consumer request and DWORD ADD512 are static projections; full aggregation and final policy remain external.",
            )
        )
    if has_fire_event_consumer:
        issues.append(
            SemanticIssue(
                "fire_event_resolved_runtime_name_required",
                "Wire suffix is only a name-recipe candidate; actual getter binding, VDLL namespace, successful publication/epoch and resource state remain external. It is not a registered event map, generic IoC or final policy.",
            )
        )
    if has_vdll_api_consumer:
        issues.append(
            SemanticIssue(
                "vdll_api_runtime_bindings_required",
                "Copied module/selector does not establish active VDLL exports or membership. Four known host gates, selected runtime tables and epoch are external; this metadata is not a generic API IoC or whole trust verdict.",
            )
        )
    if has_vfs_link_consumer:
        issues.append(
            SemanticIssue(
                "vfs_link_runtime_map_order_required",
                "Pair eligibility is not callback success or completed insertion; active map history, object-store resources and query normalization remain external. This is linkage metadata, not an IoC.",
            )
        )
    if has_vbasic_path_consumer:
        issues.append(
            SemanticIssue(
                "vbasic_path_backend_and_resolved_field_required",
                "Only resolved VBProjectInfo/parser-field UTF8 true-query preparation is projected; mapping/parser/version, original resources, Boost traits and final policy remain external.",
            )
        )
        if not parsed.data_raw or parsed.data_raw[-1] != 0:
            issues.append(
                SemanticIssue(
                    "vbasic_path_nonnull_pattern_profile_unsupported",
                    "Outside non-NULL registration profile, without declaring wire malformed or inferring NULL finalize.",
                )
            )
    if has_pdb_path_consumer:
        issues.append(
            SemanticIssue(
                "pdb_path_backend_and_resolved_mappings_required",
                "Only first-entry RSDS source preparation over explicit resolved mappings is projected; Boost w32 locale/compiler, attributes/NID/SNID/basename and reporting policy remain external.",
            )
        )
        if not parsed.data_raw or parsed.data_raw[-1] != 0:
            issues.append(
                SemanticIssue(
                    "pdb_path_nonnull_pattern_profile_unsupported",
                    "Outside non-NULL pattern registration, without declaring generic wire malformed or inferring NULL finalize.",
                )
            )
    if has_raw_body_consumer:
        issues.append(
            SemanticIssue(
                "raw_body_explicit_views_and_policy_boundary",
                "Two independent metadata views supply full explicit byte spans and policy0/1 in order; the strict byte language does not model general Boost grammar or final network policy.",
            )
        )
        if not parsed.data_raw or parsed.data_raw[-1] != 0:
            issues.append(
                SemanticIssue(
                    "raw_body_nonnull_pattern_profile_unsupported",
                    "Outside non-NULL pattern registration, without declaring generic wire malformed or inferring NULL finalize.",
                )
            )
    if has_raw_ssl_consumer:
        issues.append(
            SemanticIssue(
                "raw_ssl_explicit_span_and_policy_boundary",
                "A strict fixed-byte subset supplies local predicate/YARA on the exact selected raw remaining span; original compiler/resources/namespace and ProcessMatchedSignature remain external.",
            )
        )
        if not parsed.data_raw or parsed.data_raw[-1] != 0:
            issues.append(
                SemanticIssue(
                    "raw_ssl_nonnull_pattern_profile_unsupported",
                    "Outside non-NULL pattern registration, without declaring generic wire malformed or NULL finalize.",
                )
            )
    if has_ssl_cert_consumer:
        issues.append(
            SemanticIssue(
                "ssl_cert_backend_and_runtime_view_required",
                "Only pattern input and parsed-runtime ASCII DN/raw validity recipes are projected; "
                "ASN.1 parsing, regex/NRI/namespace and final policy remain external.",
            )
        )
    if has_generic_regex_consumer:
        issues.append(
            SemanticIssue(
                "generic_regex_backend_required",
                "The generic pattern manifest requires the original Boost w32 byte backend; "
                "Lua subject generation, runtime order/name resolution and final policy are external.",
            )
        )
    if has_http_url_consumer:
        issues.append(
            SemanticIssue(
                "http_url_backend_required",
                "The manifest requires the engine Boost w32 byte-regex backend; "
                "there is no portable regex evaluator or final network verdict.",
            )
        )
    if callback_target is None:
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "No registration target or consumer semantics are confirmed "
                "for this callback index.",
                details=(("callback_index", parsed.callback_index),),
            )
        )
    elif business_semantics == "unknown":
        issues.append(
            SemanticIssue(
                "ndat_callback_business_semantics_unknown",
                "The callback table target is confirmed, but this exporter does "
                "not claim its input/output business effect without a direct "
                "handler and consumer dataflow trace.",
                details=(
                    ("callback_index", parsed.callback_index),
                    ("dispatch_target", callback_target),
                ),
            )
        )
    if parsed.record_id_suffix_raw is not None:
        issues.append(
            SemanticIssue(
                "record_name_encoding_unknown",
                "The NUL-terminated bytes are passed to createrecidz as a name, "
                "but their text encoding is not established.",
            )
        )
    if parsed.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_uninterpreted",
                "Bytes following the first record-name terminator are retained "
                "without confirmed receiver semantics.",
                details=(("length", len(parsed.trailing_raw)),),
            )
        )
    status = (
        "unsupported"
        if parsed.trailing_raw
        else "confirmed_subset"
        if callback_target is not None
        else "observed_only"
    )
    if has_http_url_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "http_url_nonnull_pattern_framing_unsupported",
                "The manifest requires nonempty counted data ending in NUL; it does not model NULL finalize or compile failure.",
            )
        )
    if has_generic_regex_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "generic_regex_nonnull_pattern_profile_unsupported",
                "The projector requires nonempty counted data ending in NUL; this is not "
                "a wire-framing verdict or proof that the loader supplies NULL for zero length.",
            )
        )
    if has_ssl_cert_consumer and (not parsed.data_raw or parsed.data_raw[-1] != 0):
        issues.append(
            SemanticIssue(
                "ssl_cert_nonnull_pattern_profile_unsupported",
                "Nonempty counted data ending in NUL defines this projector's non-NULL "
                "registration profile, not a wire rejection or inferred NULL finalize.",
            )
        )
    return RuleSemantics(
        status=status,
        representation="ndat.counted_data_callback_suffix.v4",
        data=JSONObject(
            (
                ("type", "NDAT"),
                ("raw_hex", parsed.raw.hex()),
                ("data_length", parsed.data_length),
                ("data_raw_hex", parsed.data_raw.hex()),
                (
                    "callback",
                    JSONObject(
                        (
                            ("index", parsed.callback_index),
                            ("index_hex", f"0x{parsed.callback_index:02x}"),
                            ("dispatch_target", callback_target),
                            ("dispatch_mechanism_confirmed", True),
                            ("dispatch_target_confirmed", callback_target is not None),
                            ("business_semantics", business_semantics),
                            (
                                "is_final_detection",
                                False
                                if parsed.callback_index in callback_semantics
                                else None,
                            ),
                        )
                    ),
                ),
                (
                    "record_name_raw_hex",
                    parsed.record_id_suffix_raw.hex()
                    if parsed.record_id_suffix_raw is not None
                    else None,
                ),
                ("trailing_raw_hex", parsed.trailing_raw.hex()),
                *(
                    (("vdll_api_attribute", _api_attribute_manifest(parsed)),)
                    if has_api_attribute_consumer
                    else ()
                ),
                *(
                    (("vdll_fire_event", _fire_event_manifest(parsed)),)
                    if has_fire_event_consumer
                    else ()
                ),
                *(
                    (("vdll_api_membership", _vdll_api_manifest(parsed)),)
                    if has_vdll_api_consumer
                    else ()
                ),
                *(
                    (("vfs_link", _vfs_link_manifest(parsed)),)
                    if has_vfs_link_consumer
                    else ()
                ),
                *(
                    (("vbasic_path_pattern", _vbasic_path_manifest(parsed)),)
                    if has_vbasic_path_consumer
                    else (("pdb_path_pattern", _pdb_path_manifest(parsed)),)
                    if has_pdb_path_consumer
                    else (("raw_body_pattern", _raw_body_manifest(parsed)),)
                    if has_raw_body_consumer
                    else (("raw_ssl_pattern", _raw_ssl_manifest(parsed)),)
                    if has_raw_ssl_consumer
                    else (("ssl_cert_pattern", _ssl_cert_manifest(parsed)),)
                    if has_ssl_cert_consumer
                    else ()
                ),
                *(
                    (("generic_regex_pattern", _generic_regex_manifest(parsed)),)
                    if has_generic_regex_consumer
                    else ()
                ),
                (
                    "http_url_pattern",
                    _http_url_manifest(parsed) if has_http_url_consumer else None,
                ),
                (
                    "process_stage_contract",
                    _process_stage_contract() if has_logskip_consumer else None,
                ),
                (
                    "loader_handoff",
                    JSONObject(
                        (
                            ("entry_stride", 0x18),
                            ("record_id_entry_offset", 0x04),
                            ("record_id_descriptor", 0x1017),
                            ("record_id_is_wire_dword", False),
                            (
                                "record_id_source",
                                "createrecidz"
                                if parsed.record_id_suffix_raw is not None
                                else "createrecid",
                            ),
                            ("record_id_value", None),
                            (
                                "record_id_value_requirement",
                                "loader context and record-ID creation state",
                            ),
                            ("post_callback_record_id_argument", 3),
                        )
                    ),
                ),
                (
                    "record_name_role",
                    "absent"
                    if parsed.record_id_suffix_raw is None
                    else "nul_terminated_name_for_createrecidz",
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 ReceiveNewTemplate 0x1803224D0/0xB70",
            "mpengine 1.443.903.0 NdatPostCallback 0x180464800/0x186",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41",
            "mpengine 1.443.903.0 logskip_init_module 0x180B54A70/0x12F",
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D",
            "mpengine 1.443.903.0 callback table base 0x181280FF0; NdatPostCallback table[index] read 0x180464883",
            "mpengine 1.443.903.0 dllsupp_init 0x180CA6240/0x6E0 writes indices 3,4,7 at 0x180CA67D1/0x180CA67E6/0x180CA67F4",
            "mpengine 1.443.903.0 fssupp_init 0x18048B180/0x1C7 writes index 6 at 0x18048B283",
            "mpengine 1.443.903.0 filepathscan_init 0x180CAC350/0x67 writes indices 1,2,10,11",
            "mpengine 1.443.903.0 cksig_init_module 0x1805648A0/0x31D initializes table and writes indices 8,12,14",
            "mpengine 1.443.903.0 vlib_init_module 0x180C50820/0x156 writes index 13",
            "mpengine 1.443.903.0 NetworkHips_init_module 0x180C75A60/0x1BB writes indices 15-20",
            "mpengine 1.443.903.0 hips_init_module 0x18048C8E0/0x7A2 writes index 21",
            "mpengine 1.443.903.0 retarget_init_module 0x180BDDF60/0x163 writes index 23",
            "mpengine 1.443.903.0 callback bodies lookup: VbasicPathNdatCallback 0x1805861F0/0x15; VdllNdatDontCountCallback 0x180CA5640/0x201; VdllNdatFireEventCallback 0x180CA5850/0x48C; VdllNdatVfsLinkCallback 0x180429B00/0x287; VdllNdatApiAttributeCallback 0x180CA53F0/0x247",
            "mpengine 1.443.903.0 callback bodies lookup: RkpatCallback 0x18055BBD0/0xC3; PdbPathNdatCallback 0x180573920/0x15; DnsCacheInfoNdatCallback 0x180BBAE20/0x10C; GenericRegExpNdatCallback 0x1804B3FA0/0x8A",
            "mpengine 1.443.903.0 callback bodies lookup: HttpUrlNdatCallback 0x180526C00/0xC8; HttpHeaderNdatCallback 0x1805BA660/0xC5; MsgBodyNdatCallback 0x180C75990/0xC5; SSLCertNdatCallback 0x18055D720/0xC5; RawBodyNdatCallback 0x1804B4E70/0xBE; RawSSLCertNdatCallback 0x1804B4DA0/0xC8",
            "mpengine 1.443.903.0 callback bodies lookup: AsrAutoEnableNdatCallback 0x1805BC650/0x228; McpServersNdatCallback 0x180BDF100/0xA9",
            "mpengine 1.443.903.0 LogSkip::Initialize 0x180B53F80/0x41 writes indices 5 and 22",
            "mpengine 1.443.903.0 LogSkipNdatCallback 0x18005B7C0/0x68",
            "mpengine 1.443.903.0 CAsrNotAllowedNdatCallback 0x1805009C0/0x59",
            "mpengine 1.443.903.0 LogSkip::AddString 0x18005C630/0xE66",
            "mpengine 1.443.903.0 CustomAsrIsNotAllowed 0x180B53EF0/0x8E",
            "mpengine 1.443.903.0 LogSkip::Check 0x180287DE0/0x1104",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            *(
                (
                    SemanticClaim(
                        "ndat-vdll-api-attribute-metadata",
                        "runtime_consumer",
                        "Callback7 copies counted module!selector:attribute into128-byte CStrings. Named CRC includes only bytes before the first colon; ordinal parsing sees the full tail. RuntimeRecID is unused. Explicit kstore outcomes project attribute CString storage and partial NULL failure; successful map history keeps first host/fullu64key value. The static pre-only exact-VA consumer requests aggregation and adds512 to a DWORD with wrap, ignoring the aggregation return.",
                        "subset",
                        ("ndat-api-attribute-static", "ndat-api-attribute-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Wire bytes do not prove loaded tables, native object storage, borrowed-pointer lifetime, map insertion or an active epoch. Native38 uses module-index and owned CString services; aggregation/counter behavior is static only. Whole pe_notify, resource exceptions and final disposition remain external.",
                            ),
                        ),
                    ),
                )
                if has_api_attribute_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-vdll-fire-event-metadata",
                        "runtime_consumer",
                        "Callback4 uses runtimeRecID through namefromrecid before copied DLL/API resolution. A resolved name selects optional# and case-sensitive E post phase, a fullDWORD event and two typed/u8-index recipes. Phase/host/API-VA maps keep first value. The traced consumer sends event low16 and gates both parameter requests on param1_type; known retrieval failure becomes empty CString without canceling the attribute call. Wire suffix is only a conditional candidate, not a confirmed getter result or registration.",
                        "subset",
                        ("ndat-fire-event-static", "ndat-fire-event-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "True RecID/getter roundtrip, successful publication/no-shadow/epoch, actual VDLL namespace and allocation/exception state are external. Native callback/type/map, controlled45suffix recipes and index0 numeric getters are separate from static whole-consumer attribution; no gueststrings/indexN, __siga_check execution or final policy is projected.",
                            ),
                        ),
                    ),
                )
                if has_fire_event_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-vdll-api-membership",
                        "runtime_consumer",
                        "Callback3 copies the counted first-! module/export selector into128-byte CStrings, ignoring copy/ordinal parse HRESULTs. Explicit selected runtime VDLL tables resolve named rawCRC XOR salt or ordinal values; nonzero resolvedVA is normalized only for host2 before bucket append. pe_is_nop_api queries fullu64 linear membership without querybit clearing. The traced x64 trust branch statically skips two counter increments and its API-limit checks on true, not every counter branch.",
                        "subset",
                        ("ndat-vdll-api-static", "ndat-vdll-api-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Real module-name resolution, active bindings/epoch/other writers, allocation/exception partial state and complete trust-switch/counter policy are outside this projection. Original native fixtures use fake selected VDLL tables plus module-index service; ordinal/truncation are synthetic, absent from969 actual records. No OS API existence, allowlist IoC, whole trust execution or final verdict is established.",
                            ),
                        ),
                    ),
                )
                if has_vdll_api_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-vfs-link-metadata",
                        "runtime_consumer",
                        "Callback6 projects the counted first-> pair via bounded copies and signed-byte WCHAR widening, without terminal-NUL requirement or unescaping. Four identical native insertion attempts use CRCUpperStringW as the sole key; the successful map keeps the first value. RuntimeRecID is unused. pe_getvfslink returns the target pointer; linkedVfsFileExists checks original existence first, then normalization and non-NULL redirect presence without rechecking the target.",
                        "subset",
                        ("ndat-vfs-link-static", "ndat-vfs-link-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Portable pair eligibility is not callback success or completed insertion. Successful runtime order/initial map, real object storage, allocation/exception partial state, normalization/current directory, reset/alias writers and full VFS remain external. CRC collisions and the complete linked-exists chain are static attribution, not covered by the bounded native fixtures. This is linkage metadata, not a detection/allowlist IoC or final verdict.",
                            ),
                        ),
                    ),
                )
                if has_vfs_link_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-vbasic-path-pattern-source-contract",
                        "runtime_consumer",
                        "Callback1 stores first-NUL Boost patterns through actual PushRegEx flags0x100000. The traced source is VBProjectInfo+0x2A522B copied to parser+0xB0; the worker copies520B, forcesWCHAR259NUL and converts CP_UTF8 flags0/-1 into260bytes. Only API-success nonempty UTF8 prepares the true regex query; its caller hash length includesNUL. Separate low-byte recovery passes false and bypasses regex vectors.",
                        "subset",
                        ("ndat-vbasic-path-static", "ndat-vbasic-path-native-oracle"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Resolved field projection is not the original VB/PE parser or worker; resource/API failures outside capacity domain, global patterns, general Boost grammar/traits/namespace and hash/NID/SNID/ShouldContinueScanning policy remain external. Arbitrary compile/match/verdict unknown.",
                            ),
                        ),
                    ),
                )
                if has_vbasic_path_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-pdb-path-pattern-source-contract",
                        "runtime_consumer",
                        "Callback10 stores first-NUL Boost byte patterns through original PushRegEx with flags0x100000 and row RecID+16. The traced scan_debugdir caller selects a mapped first-entry CodeView RSDS path CString at+24, using SizeOfData-23 as original string bound and rejecting empty paths. scan_filepath supplies the original full path to CString Match; basename and earlier NID/SNID/attribute paths are separate.",
                        "subset",
                        ("ndat-pdb-path-static", "ndat-pdb-path-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Resolved mapped snapshots do not implement a PE mapper/window/cache lifecycle; full compiler/traits/locale acceptance, upstream mapping failures and ShouldContinueScanning/delayed-report/namespace policy remain external. Arbitrary new pattern compile/match/verdict is unknown.",
                            ),
                        ),
                    ),
                )
                if has_pdb_path_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-raw-body-byte-predicate",
                        "runtime_consumer",
                        "Callback19 constructs first-NUL Boost binary patterns with flags0x400000. Two independent metadata views at+0x30/+0x38 supply full buffer/u32 ranges in order, with policy0/1. A bounded immutable byte AST provides case-sensitive local search and YARA on the same explicit span; dot covers256bytes, anchors only fixed literals with observed0A/0C/0D/85 or span boundaries.",
                        "subset",
                        ("ndat-raw-body-static", "ndat-raw-body-native-differential"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Upstream view roles/decoding, global-vector presence, general regex acceptance, native exceptions/resources and runtime RecID/SigSeq/ProcessMatchedSignature are outside the local predicate; no HTTP event or final verdict.",
                            ),
                        ),
                    ),
                )
                if has_raw_body_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-raw-ssl-byte-predicate",
                        "runtime_consumer",
                        "Callback20 constructs first-NUL Boost w32 patterns with syntax flags0x400000; binary Search uses explicit pointer+length. A nonempty fixed byte/negated-single-byte subset provides Boolean search and hex YARA on the same selected span. The metadata view selects buffer[6:size]; BE24 length gates bounds and selects a separate parser span, not the raw remaining range.",
                        "subset",
                        ("ndat-raw-ssl-static", "ndat-raw-ssl-native-differential"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Complete regex acceptance, native exceptions/resources, upstream metadata, runtime RecID/SigSeq and ProcessMatchedSignature remain outside the local predicate; no certificate trust or final verdict.",
                            ),
                        ),
                    ),
                )
                if has_raw_ssl_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-ssl-cert-pattern-contract",
                        "runtime_consumer",
                        "Callback18 (0x12) stores first-NUL Boost w32 byte patterns with flags0x500000. "
                        "The consumer searches formatted Subject/Issuer DN and validity strings, not raw certificate bytes. "
                        "278 frozen corpus patterns compiled and 1652 backend queries completed; arbitrary compile validity is not projected.",
                        "subset",
                        ("ndat-ssl-cert-static", "ndat-ssl-cert-backend-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Complete certificate parsing, default-LCID traits, runtime RecID/SigSeq/NRI and ProcessMatchedSignature policy remain outside the data projector.",
                            ),
                        ),
                    ),
                    SemanticClaim(
                        "ndat-ssl-cert-subject-recipes",
                        "runtime_consumer",
                        "Parsed runtime DN rows use fixed type order and first matching row, preserving NULL masking/empty values/CString boundaries; the narrow success projection is ASCII. "
                        "Validity formats raw SYSTEMTIME words and four unsigned DWORDs with minimum decimal widths and a zero-year local gate, without current-time logic.",
                        "subset",
                        (
                            "ndat-ssl-cert-static",
                            "ndat-ssl-cert-formatter-native-host",
                            "ndat-ssl-cert-builders-native-host",
                        ),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Subject availability is recipe-local: global pattern presence, CRT/resource failure, ASN.1/OID mapping, field NRI checks and regex/post-match policy are not modeled; non-ASCII selected values are typed unsupported, not false.",
                            ),
                        ),
                    ),
                )
                if has_ssl_cert_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-generic-regex-pattern-contract",
                        "runtime_consumer",
                        "Callback decimal13 (0x0D) forwards raw counted bytes to a first-NUL "
                        "Boost w32 narrow-char pattern with flags0x400000, preserving leading04. "
                        "The Lua arg2 CString consumer searches rows in runtime order; its first "
                        "match resolves RecID/name and returns Lua values, not a scan verdict. "
                        "Pinned-host evidence compiled 82 frozen corpus patterns and completed "
                        "410 queries; the data projector does not validate arbitrary regexes.",
                        "subset",
                        ("ndat-generic-regex-static", "ndat-generic-regex-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Default-LCID traits, upstream Lua subject encoding/coercion, runtime "
                                "row order and namespace/name resolution remain dependencies. Lua errors, "
                                "allocation/compiler failure and full Lua/outer policy execution are "
                                "not projected; no portable regex evaluator or business-domain label.",
                            ),
                        ),
                    ),
                )
                if has_generic_regex_consumer
                else ()
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-http-url-pattern-contract",
                        "runtime_consumer",
                        "Callback decimal 15 (0x0F) stores a first-NUL byte pattern "
                        "for the engine Boost w32 narrow-char backend with raw flags "
                        "0x500000. The original URI WCHAR CString is converted to UTF8 "
                        "for find_imp search; RecID/SigSeq post-match policy is separate. "
                        "Pinned-host validation compiled the frozen 226 corpus patterns "
                        "and completed 686 queries, not arbitrary-pattern validation.",
                        "subset",
                        ("ndat-http-url-static", "ndat-http-url-native-host"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Traits depend on runtime default LCID; its internal cached "
                                "value was not read. Compile/API/resource failure, arbitrary "
                                "grammar portability, upstream URI canonicalization, actual "
                                "NetworkHipsMatch execution and ProcessMatchedSignature policy "
                                "remain outside the manifest projector.",
                            ),
                        ),
                    ),
                )
                if has_http_url_consumer
                else ()
            ),
            SemanticClaim(
                "ndat-wire-framing",
                "wire_layout",
                "NDAT frames counted data, a callback index, and an optional NUL-terminated record-ID suffix.",
                "subset",
                ("ndat-wire-evidence",),
                (
                    SemanticUnknown(
                        "wire_layout",
                        "The data blob schema is callback-specific.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-callback-dispatch",
                "loader_dispatch",
                "The callback index dispatches through the registered callback table.",
                "subset",
                ("ndat-dispatch-evidence",),
                (
                    SemanticUnknown(
                        "loader_dispatch",
                        "The per-callback payload schema is callback-specific.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-record-id-handoff",
                "receiver_transform",
                "Descriptor 0x1017 creates the normalized entry +0x04 record ID "
                "with createrecid or createrecidz; NdatPostCallback passes it as "
                "callback argument 3. This DWORD is not a wire flags field.",
                "subset",
                ("ndat-record-id-receiver-evidence",),
                (
                    SemanticUnknown(
                        "receiver_transform",
                        "The numeric record ID depends on loader context and "
                        "record-ID creation state; suffix bytes alone do not "
                        "establish its value.",
                    ),
                ),
            ),
            SemanticClaim(
                "ndat-callback-schema",
                "runtime_consumer",
                (
                    "For callback 5/22 accepting non-null data (callback 5 "
                    "outside the sandbox), the loader-created record ID is "
                    "passed as LogSkip::AddString argument 4. On the ordinary "
                    "LogSkipEntry path it is stored at +0x6C; the trusted-process "
                    "branch does not forward that ID. ConfirmMatch's "
                    "full-success path copies "
                    "it to out_record_id; Check uses that value for WPP logging. "
                    "The separate +0x60 process flags derive from rule-string "
                    "prefixes, not the loader DWORD. This traces ingestion and "
                    "record-ID provenance, not a complete matching predicate."
                    if has_logskip_consumer
                    else "The backend-specific HttpUrl pattern and URI contract "
                    "is exported separately; complete compiler and post-match "
                    "policy are not projected."
                    if has_http_url_consumer
                    else "The generic Boost pattern and Lua byte-subject contract is "
                    "exported separately; complete compiler and first-match namespace "
                    "behavior are not projected."
                    if has_generic_regex_consumer
                    else "The formatted-certificate pattern/subject contract is exported separately; complete parser, NRI and query policy are not projected."
                    if has_ssl_cert_consumer
                    else "The raw binary pattern/explicit remaining-span contract and strict byte predicate are exported separately; compiler and post-match policy remain external."
                    if has_raw_ssl_consumer
                    else "The raw body pattern, two ordered binary views and strict byte predicate are exported separately; upstream view roles and post-match policy remain external."
                    if has_raw_body_consumer
                    else "The PDB path pattern and first-entry mapped RSDS source contract are exported separately; complete mapping, attributes/NID/SNID and reporting policy remain external."
                    if has_pdb_path_consumer
                    else "The VBProjectInfo/parser-field UTF8 true-query and pattern contract are exported separately; low-byte recovery is not a regex subject and complete loader/reporting policy remain external."
                    if has_vbasic_path_consumer
                    else "The counted VFS redirect pair and CRC-keyed map contract are exported separately; successful runtime insertion order and full VFS services remain external."
                    if has_vfs_link_consumer
                    else "The copied module/selector and selected runtime VDLL export/membership algorithms are exported separately; active bindings, resources and full trust-switch effects remain external."
                    if has_vdll_api_consumer
                    else "The copied API and conditional wire-name event recipe are exported separately; resolved getter/VDLL bindings, publication and whole consumer policy remain external."
                    if has_fire_event_consumer
                    else "The copied selector/attribute and explicit store/map contracts are exported separately; original object storage, active epoch and aggregation execution remain external."
                    if has_api_attribute_consumer
                    else "The callback target does not establish a traced "
                    "callback-specific schema or downstream business effect."
                ),
                "subset" if has_logskip_consumer else "unknown",
                ("ndat-logskip-consumer-evidence",) if has_logskip_consumer else (),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        (
                            "The complete callback-specific rule grammar, "
                            "matching behavior, and downstream policy are not "
                            "modeled; alternate AddString storage paths are "
                            "outside this ordinary-entry claim. ConfirmMatch "
                            "also has an early-success "
                            "path that does not write out_record_id."
                            if has_logskip_consumer
                            else "Complete compiler acceptance, caller context "
                            "and post-match policy are not modeled."
                            if has_http_url_consumer
                            else "Lua subject generation, actual vector/namespace state "
                            "and complete compiler/query errors remain external."
                            if has_generic_regex_consumer
                            else "Full certificate parser, non-ASCII CRT conversion and regex/NRI/post-match state are external."
                            if has_ssl_cert_consumer
                            else "Whole Boost grammar, upstream metadata and native exception/resource/namespace/post-match state remain external."
                            if has_raw_ssl_consumer
                            else "Upstream view roles/decoding, whole Boost grammar and native exception/resource/namespace/post-match state remain external."
                            if has_raw_body_consumer
                            else "Complete mapped-window lifecycle, runtime Boost traits/compiler and ShouldContinueScanning/delayed-report state remain external."
                            if has_pdb_path_consumer
                            else "Original VB/PE mapping/version/parser and worker execution, native resources, Boost traits and ShouldContinueScanning/reporting remain external."
                            if has_vbasic_path_consumer
                            else "Actual map history/epoch, resource failures, query normalization and complete VFS effects remain external."
                            if has_vfs_link_consumer
                            else "Real module resolution, active VDLL/membership state and complete trust-counter/resource policy are external."
                            if has_vdll_api_consumer
                            else "Actual runtime name, map/guest state, allocations and __siga_check policy are external; wire candidate is not a confirmed getter value."
                            if has_fire_event_consumer
                            else "Actual VDLL tables, object-store resources/borrowed lifetime, successful map history, aggregation execution and final policy remain external."
                            if has_api_attribute_consumer
                            else "Callback-specific schema and effects are "
                            "unresolved for this record."
                        ),
                    ),
                ),
            ),
            *(
                (
                    SemanticClaim(
                        "ndat-process-stage",
                        "runtime_consumer",
                        "For callback 5/22, the suffix-prepared process field's "
                        "leading '>', '<', '!', '?' characters OR bits 1/2/4/8 without "
                        "whitespace trimming. After the stream gate, a leading "
                        "'*' or empty process with PID 4 selects early success, "
                        "skipping interface/output writes; otherwise mask 0x04 "
                        "selects the ComparePartialProcessName callee, not "
                        "negation. A later "
                        "interface may overwrite the comparison result.",
                        "subset",
                        ("ndat-process-stage-static", "ndat-process-stage-native"),
                        (
                            SemanticUnknown(
                                "runtime_consumer",
                                "Wire UTF-8/NUL ingestion, field splitting, "
                                "GetEFlags suffix conversion, expansion, "
                                "comparison callees and interface behavior are "
                                "outside the portable prefix stage.",
                            ),
                        ),
                    ),
                    SemanticClaim(
                        "ndat-stream-gate",
                        "detection_predicate",
                        "Only ConfirmMatch's mode/event subpredicate is modeled: "
                        "null stream bypasses it; otherwise mask 0x03 equal to zero "
                        "allows any mode, or mask 0x01 permits mode 0 and mask "
                        "0x02 mode 1 (union). Mask 0x08 additionally requires event 5. Other "
                        "DWORD bits do not participate in this gate.",
                        "subset",
                        ("ndat-stream-gate-static", "ndat-stream-gate-native"),
                        (
                            SemanticUnknown(
                                "detection_predicate",
                                "A valid caller/PID context and other rule "
                                "checks are required; gate success is not a "
                                "complete match. Native cases cover flags "
                                "0..15, not every DWORD; ignoring higher bits "
                                "follows the static masks.",
                            ),
                        ),
                    ),
                )
                if has_logskip_consumer
                else ()
            ),
            SemanticClaim(
                "ndat-verdict",
                "final_verdict",
                "NDAT framing and callback dispatch do not establish a broad business interpretation or final verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict",
                        "The callback and downstream policy do not establish final disposition.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            *(
                (
                    SemanticEvidence(
                        "ndat-api-attribute-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-vdll-api-attribute-metadata",),
                        "VdllNdatApiAttributeCallback180CA53F0/247: ignored copy128 HRESULT, first colon, namedCRC beforecolon/ordinal fulltail; kstore1800FB54C flags0 with NUL; Emplace40020C/DC first-wins pointer map E00+64bucket+16host. pe_notify_api_call1800B1C50/635 pre-only exact-u64 query, callB202C MpAggregateAttributeEx, ADD DWORD pe+AAB30,200h atB2031. RecID unused; objectstore pages and lifecycle external. docs/mpengine.dll/1.443.903.0/ndat_api_attribute_contract_private.md.",
                    ),
                    SemanticEvidence(
                        "ndat-api-attribute-native",
                        "consumer",
                        "engine_runtime",
                        "Original callback/CRC/export/map with explicit module-index and owned CString services",
                        ("ndat-vdll-api-attribute-metadata",),
                        "tests/local_cb7_native_v1.py SHA61d7921a22e3f5570dce40702fae43db4d6772635269b3ebb467ada8ee4ced16 results02cc4e9fdb1c07ef2570f53bb79ec29b7f574030a8d41dd42e8ebd0b419f806c:38children,6actualdata+32synthetic; executable relocation-aware/eight CRC tables/global restore readback/guarded maps and owned value capture verified. Root subset0,34,36 resultsae8525ae716572423b3d12090103a1a304b9e0e4a5c5bfb62eb0d613da6a1f9a. Consumer/aggregation/ADD not executed; attempt1 separate harness shadow failure. Offline bridges: tests/local_vdll_api_attribute_bridge.py and tests/local_ndat_api_attribute_bridge.py. docs/mpengine.dll/1.443.903.0/ndat_api_attribute_contract_current_private.md.",
                    ),
                )
                if has_api_attribute_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-fire-event-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-vdll-fire-event-metadata",),
                        "VdllNdatFireEventCallback180CA5850/48C -> namefromrecid1800A9AE0; original copied API lookup, GetParamTypeFromSpecifier1805A84C8/43, insert4001E0/2B -> Emplace40020C/DC. pre600/postA00 maps in g_hashtables1812748A0. pe_notify_api_call1800B1C50/635 uses low16event and double param1_type gate; pe_GetParamData1803D22F8/3A6 gets runtime parameters. ReceiveNewTemplate322983 passes raw suffix to createrecidz, but publication/no-shadow/getter binding remains conditional. docs/mpengine.dll/1.443.903.0/ndat_fire_event_contract_private.md.",
                    ),
                    SemanticEvidence(
                        "ndat-fire-event-native",
                        "consumer",
                        "engine_runtime",
                        "Original callback/map/type plus separate controlled candidate and index0 numeric getter jobs",
                        ("ndat-vdll-fire-event-metadata",),
                        "tests/local_cb4_native_v1.py SHA745b79424ed6d07dd0ceacfeb630c4c712a4f7514b62e58f9cfe13f402b616cb resultsb2f5747f6b8fcdcbe7855935ec0e669757a79c02a5ef7a09ac5a70163f96705c:90children/89fixtures,512typecalls,282primaryentries; 45actualdata used one independent runtime-name fixture, no suffixroundtrip. local_cb4_corpus_recipe_native_v1.py SHA1c4c87d668d6cced3cedc0238dba4ee4a556e2ebdfd0438bdf7da20b120bcfe1 results9deaf488cd84a42478d28f84e5371dd47ee608a8ed032345a547c0f33b9cb4bc:45controlled name services/180entries, still not trueRecIDroundtrip. local_cb4_param_getter_native_v1.py SHAedfb32a6f096320043c66891841d63779ec95474da4fa037a7596d6c2890b900 results5a48a2a4cfcf42635bb0b1196095e3f346141dca9653b295f1ec55324e7178ef:132index0calls/66u32reg50services, no gueststrings or wholeconsumer. Backend services and fakeVDLL tables are explicit; old main job globals had writeback without readback assertions, new45 job adds readback. Hooks isolated by childexit, not fullrestore/PCtrace."
                        " Current offline bridges: tests/local_vdll_fire_event_bridge.py SHA5f2fe77464030b2e79aced70039660de93eb8a8434b0ecd64fe15617fc548141; tests/local_ndat_fire_event_bridge.py SHA1ee32146c8dff69128dd29376160b57a35c74aa65061d77dd4003978750ff316.",
                    ),
                )
                if has_fire_event_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-vdll-api-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-vdll-api-membership",),
                        "VdllNdatDontCountCallback180CA5640/201 -> StringCchCopyNA180321570/69, CRC_1(copied selector CString after127-byte truncation, excludingNUL), StrToULongHelper1801D135C/11E, vdll_get_export_va180100F70/54 or by_ordinal180101F70/A1 -> g_hashtables1812748A0 vectors16x4. pe_is_nop_api18041E6C0/5B linear query; trust_change_callback<x86_64_context>180C5B108/409 callC5B3FA ALtrue bypasses selected837C0/837C4 counters/API-limit, not other counter branches. docs/mpengine.dll/1.443.903.0/ndat_dont_count_contract_private.md.",
                    ),
                    SemanticEvidence(
                        "ndat-vdll-api-native",
                        "consumer",
                        "engine_runtime",
                        "Original callback/export/membership with explicit module-index service; separate CRC/parser oracles",
                        ("ndat-vdll-api-membership",),
                        "tests/local_cb3_native_v1.py SHAb380b320a7977ed38b9a685e81d8a49b4f39fe8f5271c6a00dc6b12cf4d6a9fa; results c36d3365b55083e096412f9ad1c5bf1ca102ced4aa6fd78e072623d66f1b507f: 32children/64callback calls/384membership queries, not repeat-append matrix or real VDLL loading. Separate local_cb3_crc_native_corpus_v1.py SHA945374128f9cf05d876cc148d6cac7df738a756473487501b282afa91a058edf results a06d962cf2a0f95eb2fb27cdc128ced871f71f88cc2ccf5d03975c891a1c0a36 covers969selectors+256singlebytes/full8tables; local_cb3_parser_native_v1.py SHA37b1d31299d69b3ff50101dee5c9134f47c60052ddcb6bd43e3bd3bc9469b738 results be66f9c4b6a74098bd297d000fea761e90a77786efe1d550c1337c1796f9a430 covers80rawparser calls. Current offline bridges: tests/local_vdll_api_membership_bridge.py SHA7e4595f67f25b6e61d03093ee1d10544c07aca6d9caa9a037200d02b5c600833; tests/local_ndat_vdll_api_bridge.py SHA0265ef13ce80a3e324e4e1557a8982fe3d9abfbce97e55d434121928241b6d31. Full trust-counter path/realloc/exception and real module resolver are not executed.",
                    ),
                )
                if has_vdll_api_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-vfs-link-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-vfs-link-metadata",),
                        "VdllNdatVfsLinkCallback180429B00/287 -> CRCUpperStringW180704FE0/8F, kpushobject(flags0)/kpopobject and _Emplace180429D88/10D; g_Redirects1812748B8. pe_getvfslink18034B9A4/6C; linkedVfsFileExists18034C764/99 -> VFS_NormalisePath1800C2C60/5E4. docs/mpengine.dll/1.443.903.0/ndat_vfs_link_contract_private.md. Distinct-source CRC collision identity and linked-exists call-chain behavior are static only.",
                    ),
                    SemanticEvidence(
                        "ndat-vfs-link-native",
                        "consumer",
                        "engine_runtime",
                        "Original host-DLL callback/map/CRC/query with object-store services; separate normalization controls",
                        ("ndat-vfs-link-metadata",),
                        "tests/local_cb6_native_v1.py SHA256 3e8f1503ee9e4d237e7767522965efef202016d546715ad6e2608f26ef705bfb; manifest5a5698db3020865b78185f56e63af2693fdc03b61e10433ef3e6a4feb287d8e6; results e6b19f62258947aa410b6484bb55136316f2b662aa3acfe7c454dc46efd14b85: 19 isolated children, 18 callback fixtures plus CRC/normalizer child. Owned kpush/kpop storage seams; global pointer restored, patches isolated by child exit, not full DLL restore/PC or nonvolatile tracing. No allocation failure, multikey tree or complete linked-exists execution. Offline current bridges: tests/local_vfs_link_bridge.py SHA256 e6b2338c82e9c1ed5d16fd196d303df17513fe30b1e28ef08fa5459a94c57493; tests/local_ndat_vfs_link_bridge.py SHA256 c205d5d4be890fba9cf88f174cc276910f7622b1c768da1179d97db179a6da1f.",
                    ),
                )
                if has_vfs_link_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-vbasic-path-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-vbasic-path-pattern-source-contract",),
                        "VbasicPathNdatCallback1805861F0/15 -> FilePathNdatCallback1801FB7E4 -> PushRegEx1801FC020 flags100000,row24RecID+16. Load_VBasicData1804AB7B0/3C5 mask180E43120 {2A,20A} copies VBProjectInfo+2A522B to parser+B0. scan_vbasic32_worker_core1804ABBA0/898 copies520/forcesWORD259NUL -> WCTMB65001/flags0/-1/output104hex=260bytes; nonempty call4ABD3E scan_filepath(stateAA0,path,strlen+1,true). Recovery4AC2FF false bypassesregex at144091. descriptor selector decimal11/hex0B. docs/mpengine.dll/1.443.903.0/ndat_vbasic_path_contract_private.md; conversion/source mapping is static attribution, not native complete worker.",
                    ),
                    SemanticEvidence(
                        "ndat-vbasic-path-native-oracle",
                        "consumer",
                        "engine_runtime",
                        "Original Push/Match primitive plus separate Win32 conversion oracle, not original worker",
                        ("ndat-vbasic-path-pattern-source-contract",),
                        "Current offline production bridge tests/local_ndat_vbasic_path_bridge.py SHA256 9d32c1fe4b77343b2c64d2561b1b88d06abdcee404c92218e9c5b47b25dd79b5. "
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; tests/.tmp/local_cb1_vb_native_evidence_index_v1.json SHA92659762ce7067a23d81bf32288a8729f5e5da64cdabcb1a3c162e2932681e14 pins368actualPush0/23children/1840Match/111positive37rows, manual3 primitive and17Win32oracle12success(includingempty)/5error122. Script95a719c5c9ecf301d525bff15dba43e52e5df8c78b9db2d0d67e9abc3ed04a2d; oraclefdd6bd11e55500b12c9648ab260fc51e8e1d45e9a2cc846c4b1a7d7781c0ed20/resultsb5a8165f4d3fda7bfa09a20bbca5ab4ef96efbdae4f95343a017fae5bdbe173b. Original manual raw90 subject is invalidUTF8/primitive only. New tests/.tmp/local_cb1_valid_utf8_source_witness_v1.py SHAf022ba028b2f10befbf762e90200e0241f706a591cebb86ca51d577ce0586f76/results546e093b4e3fd14eba06e8ec03bdaaa3a6afd344aca9745349e1e840cbb22bed uses actualWCTMB UTF16hex1004->D090 validUTF8 with actualraw90class Push0/Match1/case1/slash0. Root API17 replay6ed108a5949169cb8a9a8984d1843c3ac4a14db0ab7e7ceb2b4048f00dc01baf. Host codepins/canaries/children, no Unicorn trace or originalworker/parser/CRC/policy execution.",
                    ),
                )
                if has_vbasic_path_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-pdb-path-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-pdb-path-pattern-source-contract",),
                        "PdbPathNdatCallback180573920/15 -> FilePathNdatCallback1801FB7E4/105 -> PushRegEx1801FC020/3F stores RecID+16,strlen->do_assign1801FC300/E6 flags100000,row24. scan_debugdir1804B7EB0/1FB maps first debug entry Type2,AddressOfRawData+20,Size>=25,RSDS24,path+24 -> mmap_string_ex18013C100/FA(max=Size-23,outlen excludesNUL). scan_filepath180143EE4/AFE descriptor181289AB8(pathvec/namevec/selector77) -> original full CString Match1800B6D64 at1440C4 -> ShouldContinueScanning1801449E4. docs/mpengine.dll/1.443.903.0/ndat_pdb_path_contract_private.md; snapshot address/gate projection is static attribution, not executed complete mapper/consumer.",
                    ),
                    SemanticEvidence(
                        "ndat-pdb-path-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned original Windows DLL actual PushRegEx and CString Match",
                        ("ndat-pdb-path-pattern-source-contract",),
                        "Current offline production bridge tests/local_ndat_pdb_path_bridge.py SHA256 e3ed31294d8156ec1dd60214ef0bef5b2f03d9aa84ca9bcdbe0a64205b3210f4. "
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; tests/local_cb10_push_native_v2.py SHAc6ccf199144b9a1ce9eef66a935fdc69d73c59494b0d74a95e7e97f2caa5ab91; manifestff9d307a13a4877ea6215c3279d96174290781b56742952431972d4699dfd76d; .tmp/local_cb10_native_audit_v1.json SHA9a7a7061ec5ba79ccb108dec6fd974e46fca5b0fff973f5cddbec7a60de22944 pins40batches/640Push0/3200Match/201true67rows. Original zero24rows/RecID+16/padding/codepin/canary checks; no Unicorn trace, complete callback or RSDS/map/policy execution. v2 raw_utf8 was actually3f3f00 (mislabel, not Unicode failure); corrected tests/local_cb10_synthetic_utf8_native_v3.py SHAfa98646da9af2334f4d61d4f12971bbda184d6d14512f73ec3d3ec6f5a15df2c uses e6b8ace8a9a600,Push0/exact/prefix/suffix/NULafter true. Root native subset .tmp/local_cb10_native_root_subset_v1.json SHA250009b2a865c1535853e0656fe3c575125cc5e90cf3ed25238de9c6e27a07da; separate offline root audit cd0c5ab0bbf2ec900348ee33cf404c65de5fadd4f9351752c452c8a9d1c18025.",
                    ),
                )
                if has_pdb_path_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-raw-body-static",
                        "consumer",
                        "engine_static",
                        "mpengine1.443.903.0",
                        ("ndat-raw-body-byte-predicate",),
                        "RawBodyNdatCallback1804B4E70/BE -> shared append1804B4F30/reallocate1804B4F8C -> ctor1801FBFE4 flags400000,row32. NetworkHipsMatch18008E567/586 binds metadata+30/+38 views; calls8EAD0/8EB1A RegExBinaryMatch1801F10D0 with buffer+8/fullDWORDsize+4, independent NULLview/NULLbuffer/size0 gates and policy0/1. Search1801F1170 explicit unsigned iterator range -> regex_search1801F1190 matchflags400/find_imp; docs/mpengine.dll/1.443.903.0/ndat_raw_body_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-raw-body-native-differential",
                        "consumer",
                        "engine_runtime",
                        "Pinned original Windows DLL Search and YARA4.5.4 recorded-span differential",
                        ("ndat-raw-body-byte-predicate",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; tests/local_cb19_rawbody_native_v1.py SHA256 68a1245fd2b2908e61b55aa2f735d2f4e68cadfefe207f33fa0a0f2bc8a5c20f; manifest ece0794c33eaa0188f10fbeed23e96a6c2d6cd1124827f7610f6f85ea3cafdd7; results99f0ab3083b4348edc8489f73569d4ff638c23e558277dece7b9d37cf8f3c8b0. 28constructors/1554Search, dot256all and anchorboundary256controls. tests/local_cb19_yara_feasibility.py SHA256 cf0311a2b13eef62713978e715189d4ec9cf5647e59049b909c4e2bd75a44ae6; .tmp/local_cb19_yara_differential_v1.json SHAb2059dfe48fbb830cba15c825d6ca36860eb497f9940da08810cf53023d7995a: 27single+combinedcompile,1554same-span/0mismatch. Root native subsetv2 SHA111e854920c2fed2ae5896431019382c7a04df957d568df3d8bf0b1fa4dbf764 and YARA replay0215ee994ad731bbde45e79256849e956ce8692a5a6b8baaf1da8429afe46b44. Host codepins/canaries/children only; no Unicorn trace or execution of two-view caller/fullpolicy. "
                        "Current offline production bridge tests/local_ndat_raw_body_bridge.py SHA256 25d16f021d72b994cbd0727febeedd7a833eeac2ce75dab3bc8ee9c00dee5f6b.",
                    ),
                )
                if has_raw_body_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-raw-ssl-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-raw-ssl-byte-predicate",),
                        "RawSSLCertNdatCallback1804B4DA0/C8 -> append1804B4F30/5A or reallocate1804B4F8C/18F -> ctor1801FBFE4 syntax400000; row32 regex16/RecID+16/SigSeq+24. NetworkHipsMatch18008EB33 reads metadata+40 view, NULL buffer gate8EB44, size+4; 8EC2F sends buffer+6,size-6 before ParsePkcs6Certificate; RegExBinaryMatch1801F10D0 -> Search1801F1170/1F -> unsigned iterator regex_search1801F1190/180, matchflags400/find_imp; docs/mpengine.dll/1.443.903.0/ndat_raw_ssl_cert_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-raw-ssl-native-differential",
                        "consumer",
                        "engine_runtime",
                        "Pinned original Windows DLL binary Search and YARA4.5.4 recorded-span differential",
                        ("ndat-raw-ssl-byte-predicate",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; tests/local_cb20_binary_search_native_v1.py SHA256 8fdb76348d8e63aa76ae158229cc7bcb6e1683bf6f4d1f24b0a7221680526191; manifest bc7a0635b2680ffc8249f4b2e08cd89a0fa96d73ca8a4f76bc5f24e37f3ed731; results 391e6529ddf531ce65b2693f310ea8b5e1b2cc6dfdc30eb233f83579b8d96732. 118 constructors (117 corpus),1320 Search calls; tests/local_cb20_yara_differential.py SHA256 c1a657eea4cf2da36bc9b41af90b93917676f834d1044ac9a46bcca8500deaf7; .tmp/local_cb20_yara_differential_final_v2.json SHA256 3981dceb6d0d799407851e8bdd2e7edd98a34105b08406d668d388a03823b135: 117 corpus+synthetic compiled,1320 same-span comparisons/0 mismatch. Host code pins/canaries/isolated children; no Unicorn trace, metadata caller/DER parser or full policy execution. "
                        "Current offline production bridge tests/local_ndat_raw_ssl_bridge.py SHA256 fe3b290bf6d64f250118f1b4c0ddef185d8ac3d5d44b4baad4ee4d673d081839.",
                    ),
                )
                if has_raw_ssl_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-ssl-cert-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        (
                            "ndat-ssl-cert-pattern-contract",
                            "ndat-ssl-cert-subject-recipes",
                        ),
                        "SSLCertNdatCallback18055D720/C5 -> construct180549304/reallocate1801FB41C flags500000 row32; "
                        "NetworkHipsMatch18008E460 metadata+40 blob -> ParsePkcs6Certificate1801B2788; "
                        "Matchx509Dn18044DCA4 uses cert+40 Subject/+30 Issuer -> GetString1802951C0/lambda18044DF4C -> TrNewSprintfA180668528 -> CRT localeNULL; "
                        "Matchx509Validity18002E344 reads+88/+104 words and+120/+124/+128/+132 DWORDs; RegExStringMatch18002E528; "
                        "docs/mpengine.dll/1.443.903.0/ndat_ssl_cert_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-backend-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned DLL original Boost in isolated Windows children",
                        ("ndat-ssl-cert-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_cb18_corpus_probe_v1.py SHA256 4f77de32acb5c15fc5842f72e837f04353f9a5d5792682765398deaa63ee272f; "
                        ".tmp/local_boost_native_cb18_corpus_probe_v1_manifest.json SHA256 b00adb75397b2d3bcd8ee363c069737424f8432c26ec38c5536eef108e485f23; "
                        "results SHA256 a4f4b07b01dd475124a58b9223e5c43b56205e340c8a626a17f760eb202f6a4e; summary SHA256 118851b2f7e9ec69539f8a985461ffe194f49a0f89e5f4b1da14145f08349c77; "
                        "278 constructors/1652 completed queries (1390 baseline false +262 selected literal-DN witnesses true); "
                        "no original DN/certificate pipeline in this batch, no portable regex or Unicorn PC/register-trace claim; "
                        "current offline source bridge tests/local_ndat_ssl_cert_bridge.py SHA256 3a7a357b50bd8a7d0adb048484f939fde592fbbb11b61d767feb4f84874b5e63",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-builders-native-host",
                        "consumer",
                        "engine_runtime",
                        "Original DN/validity builders and CRT with downstream hooks returning false",
                        ("ndat-ssl-cert-subject-recipes",),
                        "tests/.tmp/ssl_dn_native_hook_v2.py SHA256 499f5002d6b63a4e674e1729ba024805ff07be65ebcc61db49c758c456631a7f; "
                        "manifest fd67dbd580a96db3a78109ab8c7b6621c0092a852b4b6324b1d4b41c650d037e; results 462dc94e4cabbfcf21fa822685112e6485463710eaaca145775bbcb5d9bc2924; "
                        "tests/.tmp/ssl_validity_native_hook_v1.py SHA256 04806ad5d1c7633b4f838454d239e0f3d2b4c795b1ff8b4c598667b709403dbe; "
                        "manifest 555691ebaef86b56878547a9785c5fb14c6bc6f65146cca5e872a10b6f4e6aa1; results 663aeaad5929543d984a666cd7f95104b1d21a17d5a28a0c4c1ee6880a9794df; "
                        "8 DN cases/7 subjects and 7 validity cases/4 subjects; exact code/global restoration and input canaries; "
                        "RegExStringMatch and DN CheckWSTRWSTR controlled false, not real regex/NRI policy; "
                        "root DN subset d574ca189769c7f9ca01afc15e0b0c4ce69c718003dc8a3277e5c392141f9ba1; validity subset 01337cd69595393432d63548fd0cdc8d98ac72a0617108f35ea285e2d8ef35b3; "
                        "current offline source bridge tests/local_ndat_ssl_cert_bridge.py SHA256 3a7a357b50bd8a7d0adb048484f939fde592fbbb11b61d767feb4f84874b5e63",
                    ),
                    SemanticEvidence(
                        "ndat-ssl-cert-formatter-native-host",
                        "consumer",
                        "engine_runtime",
                        "Original narrow CRT formatter in isolated Windows children",
                        ("ndat-ssl-cert-subject-recipes",),
                        "tests/local_cb18_formatter_probe_v1.py SHA256 93597d6f42592da145ef44a43ccbf20b03ec8d3e03cbf71dc4a09a5c54bb71b3; "
                        ".tmp/local_cb18_formatter_probe_v1.manifest.json SHA256 53faab4e989aefb8481637121125dbd318eb6e7506b12705c0ff7094d533d737; "
                        "results SHA256 d552cdb609ae44fa9bbadc33109d4a530cba8083fb84a1c600f4cc7bd4e12a19; "
                        "7 isolated inputs: ASCII/WCHAR-NUL/label-NUL New success then Tr same bytes; concrete mixed-BMP/astral/unpaired-surrogate inputs New E_FAIL NULL, Tr skipped; "
                        "not all non-ASCII rejection or measured CRT locale, and not original full DN/policy execution",
                    ),
                )
                if has_ssl_cert_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-generic-regex-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-generic-regex-pattern-contract",),
                        "cksig NDAT descriptor180E4DFB0:1000/100F/1002/1017 -> "
                        "ReceiveNewTemplate@1803224D0 kstore flags0 -> NdatPostCallback@180464800; "
                        "GenericRegExpNdatCallback@1804B3FA0 -> emplace@1804B402C/reallocate@1804B4108 "
                        "ctor1801FBFE4 flags400000; LsaMpCommonLib::NdatRegExpMatch@180C8FA50 "
                        "luaL_checklstring -> Match@1800B6D64 -> first RecID/name; "
                        "docs/mpengine.dll/1.443.903.0/ndat_generic_regex_contract_private.md",
                    ),
                    SemanticEvidence(
                        "ndat-generic-regex-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned mpengine 1.443.903.0 native_host isolated children",
                        ("ndat-generic-regex-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_cb13_corpus_probe_v3.py SHA256 "
                        "7a7f5ed8368222eedaf95f509d1832e1511b108c42eae39a140ac10aaa9f9721; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_manifest.json SHA256 "
                        "4993310661a2be659ca515f31f9eac634e2901bec7e622506fe125badc4f8325; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_results.jsonl SHA256 "
                        "8610c56229debbc26efaa7dc0ebb72d1b104dd332bc8d85177048e704e7e85fd; "
                        ".tmp/local_boost_native_cb13_corpus_probe_v3_summary.json SHA256 "
                        "92f22205397b35adf70845eeb4c5756bddf895931cb85dcc3f8407de9a1a5479; "
                        "current offline bridge tests/local_ndat_generic_regex_manifest_bridge.py SHA256 "
                        "0cb2a30896c8afd7fd138df1912cbf9d8e691af34aa032f559471332458e3bee; "
                        "82 constructors/410 completed queries/102 true; v2 NUL-fixture failure is historical; "
                        "loaded-code pins/canaries/timeout/child exits, no Unicorn PC/GPR/XMM trace; "
                        "host LCID1033 ACP1252 environment, not direct traits-internal locale reading; "
                        "no original Lua binding/name resolution or final scan-policy execution",
                    ),
                )
                if has_generic_regex_consumer
                else ()
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-http-url-static",
                        "consumer",
                        "engine_static",
                        "mpengine 1.443.903.0",
                        ("ndat-http-url-pattern-contract",),
                        "HttpUrlNdatCallback@180526C00; construct@180549304; "
                        "basic_regex ctor@1801FBFE4; parse@1801FE260; "
                        "regex_data@1801FC5F0 GetUserDefaultLCID; "
                        "NetworkHipsProcess@18008D8CC -> NetworkHipsMatch@18008E460 "
                        "URI input+8 -> UtilWideCharToUtf8@18066895C -> "
                        "RegExStringMatch@18002E528 -> Match@1800B6D64/find_imp@1800B55EC; "
                        "docs/mpengine.dll/1.443.903.0/NetworkHipsMatch.md",
                    ),
                    SemanticEvidence(
                        "ndat-http-url-native-host",
                        "consumer",
                        "engine_runtime",
                        "Pinned mpengine 1.443.903.0 native_host; isolated Windows child processes",
                        ("ndat-http-url-pattern-contract",),
                        "DLL SHA256 928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "tests/local_boost_native_corpus_probe_v1.py SHA256 "
                        "82f614c3374a14dfbbf9d03d13adb3bf116fdeb6209a996145a8f44fb42ca475; "
                        ".tmp/local_boost_native_corpus_probe_v1_manifest.json SHA256 "
                        "51757058c8164cbe4eb3b185289853cfc5a4c83a40050d68855b8f7cd3dab259; "
                        ".tmp/local_boost_native_corpus_probe_v1_results.jsonl SHA256 "
                        "7509a8dca0ae53df6d6fb69ea21e1ccda716300521fada2284190da1b6c47093; "
                        ".tmp/local_boost_native_corpus_probe_v1_summary.json SHA256 "
                        "d9c87becb08685f1519b324fef48e592c1a344083b0a4ad3617ee0db20b5bae1; "
                        "offline manifest/native-input bridge tests/local_ndat_httpurl_manifest_bridge.py SHA256 "
                        "a4c76ec9c16942831ccd4a12f4cd298d6d62ed6ed308a6c12974d7dd8fd02ee8; "
                        "226 constructors / 686 completed Match AL queries; loaded-code pins/canaries/"
                        "timeouts/child exits, no Unicorn PC/GPR/XMM trace; observed host LCID1033 "
                        "ACP1252 environment, not direct traits-internal locale measurement; "
                        "no full NetworkHipsMatch or ProcessMatchedSignature execution",
                    ),
                )
                if has_http_url_consumer
                else ()
            ),
            SemanticEvidence(
                "ndat-wire-evidence",
                "wire_parser",
                "engine_static",
                "ReceiveNewTemplate NDAT field decoding",
                ("ndat-wire-framing",),
            ),
            SemanticEvidence(
                "ndat-dispatch-evidence",
                "dispatch",
                "engine_static",
                "ReceiveNewTemplate / NdatPostCallback callback table and registration sites",
                ("ndat-callback-dispatch",),
            ),
            SemanticEvidence(
                "ndat-record-id-receiver-evidence",
                "receiver",
                "engine_static",
                "ReceiveNewTemplate 0x1803224D0/0xB70: descriptor 0x1017 "
                "createrecidz call 0x180322983 / createrecid call 0x1803229D5, "
                "store 0x1803226C7 to entry +4; NdatPostCallback "
                "0x180464800/0x186 reads +4 at 0x18046488C, dispatches at "
                "0x180464899 (pseudocode anchor 0x18046489F)",
                ("ndat-record-id-handoff",),
            ),
            *(
                (
                    SemanticEvidence(
                        "ndat-logskip-consumer-evidence",
                        "consumer",
                        "engine_static",
                        "LogSkipNdatCallback 0x18005B7C0/0x68 and "
                        "CAsrNotAllowedNdatCallback 0x1805009C0/0x59 forward "
                        "record ID to LogSkip::AddString 0x18005C630/0xE66 "
                        "argument 4 (v77), vector construction 0x18005CBEC; "
                        "LogSkipEntry constructor 0x180218F7C/0x140 stores "
                        "+0x6C at 0x180218FF6; ConfirmMatch "
                        "0x180288EE4/0x470 full-success output 0x18028931E; "
                        "Check 0x180287DE0/0x1104 sigseqfromrecid WPP use "
                        "0x1802881C4; process flags remain separate at +0x60",
                        ("ndat-callback-schema",),
                    ),
                    SemanticEvidence(
                        "ndat-process-stage-static",
                        "consumer",
                        "engine_static",
                        "LogSkip::AddString 0x18005C630/0xE66 process field "
                        "after GetEFlagsFromPath and before expansion; "
                        "ConfirmMatch 0x180288EE4/0x470 process dispatch and "
                        "interface CFG call 0x1802892D9 (pseudocode anchor "
                        "0x1802892DF, result overwrite)",
                        ("ndat-process-stage",),
                        "prefix 0x18005C819..0x18005C85A and remote loop blocks; "
                        "process branch 0x180289119..0x180289189",
                    ),
                    SemanticEvidence(
                        "ndat-process-stage-native",
                        "engine_equivalent_test",
                        "engine_equivalent_test",
                        "Pinned mpengine SHA256 "
                        "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "NDAT_process_prefix_differential_probe: 1372 "
                        "suffix-prepared prefix cases and 128 process branch "
                        "selections; original instruction slices with guarded "
                        "synthetic interior contexts; no comparator execution "
                        "or whole AddString ingestion",
                        ("ndat-process-stage",),
                        "prefix 0x18005C819..0x18005C85A plus remote blocks; "
                        "process selector 0x180289119..0x180289189",
                    ),
                    SemanticEvidence(
                        "ndat-stream-gate-static",
                        "consumer",
                        "engine_static",
                        "LogSkip::ConfirmMatch 0x180288EE4/0x470: DWORD masks "
                        "0x03 and 0x08 select the mode/event gate",
                        ("ndat-stream-gate",),
                        "0x180288FCD..0x180289119; reject 0x180288FC1",
                    ),
                    SemanticEvidence(
                        "ndat-stream-gate-native",
                        "engine_equivalent_test",
                        "engine_equivalent_test",
                        "Pinned mpengine SHA256 "
                        "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                        "NDAT_process_prefix_differential_probe: 640 original "
                        "stream-gate slice cases, flags 0..15, modes "
                        "0/1/2/3/0xFFFFFFFF, events 0/2/5/0xFFFFFFFF, stream "
                        "present/null with a valid synthetic PID context; "
                        "not a complete ConfirmMatch execution",
                        ("ndat-stream-gate",),
                        "0x180288FCD..0x180289119; reject 0x180288FC1",
                    ),
                )
                if has_logskip_consumer
                else ()
            ),
        ),
    )


NDAT_SPEC = FamilySpec(
    NDAT_TYPE,
    "NDAT",
    parse_ndat,
    render_ndat,
    exporter=export_ndat,
    semantic_exporter=export_ndat_semantics,
)
