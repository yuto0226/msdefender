import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..core import (
    Artifact,
    ArtifactExport,
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

NID_TYPE: Final = 0x55
SNID_TYPE: Final = 0x7E
NID64_TYPE: Final = 0xCE

_FAMILY_NAMES = MappingProxyType(
    {
        NID_TYPE: "NID",
        SNID_TYPE: "SNID",
        NID64_TYPE: "NID64",
    }
)

# These records have the same shape but use different identifier widths.
# Names intentionally describe only confirmed wire semantics.
_KEY_WIDTHS = MappingProxyType(
    {
        NID_TYPE: 4,
        SNID_TYPE: 20,
        NID64_TYPE: 8,
    }
)


@dataclass(frozen=True, slots=True)
class NidPayload:
    raw: bytes
    type_byte: int
    key_raw: bytes
    metadata_raw: int
    recid_input_raw: bytes
    identity_kind: Literal["none", "object", "unnamed", "raw"]
    object_raw: bytes | None
    ignored_trailing_raw: bytes

    @property
    def identity_text(self) -> str | None:
        """Return a display-only text view without asserting a wire encoding."""
        data = self.object_raw
        if data is None:
            return None
        if data.endswith(b"\0"):
            data = data[:-1]
        if not data or b"\0" in data:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if all(character.isprintable() for character in text) else None


def parse_nid(payload: bytes, *, type_byte: int) -> NidPayload:
    """Parse the fixed key prefix and preserve the following metadata byte."""
    try:
        key_width = _KEY_WIDTHS[type_byte]
    except KeyError as exc:
        raise ValueError(f"unsupported NID family type 0x{type_byte:02X}") from exc

    header_size = key_width + 1
    if len(payload) < header_size:
        raise ValueError(
            f"truncated {_FAMILY_NAMES[type_byte]} header: "
            f"need {header_size} bytes, have {len(payload)}"
        )

    recid_input_raw = payload[header_size:]
    object_raw: bytes | None = None
    ignored_trailing_raw = b""
    if not recid_input_raw:
        identity_kind: Literal["none", "object", "unnamed", "raw"] = "none"
    elif recid_input_raw[0] == 0:
        identity_kind = "unnamed"
        ignored_trailing_raw = recid_input_raw[1:]
    else:
        identity_kind = "object"
        nul = recid_input_raw.find(b"\0")
        if nul < 0:
            object_raw = recid_input_raw
        else:
            object_raw = recid_input_raw[: nul + 1]
            ignored_trailing_raw = recid_input_raw[nul + 1 :]

    return NidPayload(
        raw=payload,
        type_byte=type_byte,
        key_raw=payload[:key_width],
        metadata_raw=payload[key_width],
        recid_input_raw=recid_input_raw,
        identity_kind=identity_kind,
        object_raw=object_raw,
        ignored_trailing_raw=ignored_trailing_raw,
    )


def render_nid(parsed: NidPayload) -> FormatResult:
    if len(parsed.key_raw) in (4, 8):
        key_width = len(parsed.key_raw) * 2 + 2
        key = f"{int.from_bytes(parsed.key_raw, 'little'):#0{key_width}x}"
    else:
        key = parsed.key_raw.hex()

    fields = [
        ("key", key),
        ("key_raw", parsed.key_raw.hex(" ")),
        ("metadata_raw", f"0x{parsed.metadata_raw:02x}"),
    ]
    if parsed.type_byte == NID_TYPE:
        fields.append(("key_match", "exact 4-byte key; exact metadata byte"))
    elif parsed.type_byte == SNID_TYPE:
        fields.append(("key_match", "exact 20-byte key; exact metadata byte"))
    elif parsed.type_byte == NID64_TYPE:
        fields.append(("key_match", "exact 8-byte key; exact metadata byte"))
    fields.append(("record_identity", parsed.identity_kind))
    identity_text = parsed.identity_text
    if identity_text is not None:
        fields.extend(
            (
                ("identity_text", json.dumps(identity_text, ensure_ascii=False)),
                ("recid_input_raw", parsed.recid_input_raw.hex(" ")),
            )
        )
        if parsed.type_byte in (NID_TYPE, SNID_TYPE, NID64_TYPE):
            fields.append(
                (
                    "identity_role",
                    "interned RecID name; runtime checks IsAttribute()",
                )
            )
    elif parsed.recid_input_raw:
        fields.append(("recid_input_raw", parsed.recid_input_raw.hex(" ")))
    if parsed.object_raw is not None:
        fields.append(("interned_object_length", f"{len(parsed.object_raw)} B"))
    if parsed.ignored_trailing_raw:
        fields.append(("receiver_ignored_raw", parsed.ignored_trailing_raw.hex(" ")))
    return FormatResult(
        sections=(DisplaySection("Network Identifier", rows=tuple(fields)),)
    )


def _raw_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            (
                "raw_span",
                JSONObject((("offset", offset), ("length", len(raw)))),
            ),
            ("raw_hex", raw.hex()),
        )
    )


def export_nid_semantics(parsed: NidPayload) -> RuleSemantics:
    """Export the receiver-confirmed exact lookup tuple and lossless framing."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    identity_offset = key_width + 1
    identity_length = len(parsed.recid_input_raw) - len(parsed.ignored_trailing_raw)
    identity_raw = parsed.recid_input_raw[:identity_length]

    framing = JSONArray(
        (
            _raw_field("key", parsed.key_raw, 0),
            _raw_field("metadata", parsed.raw[key_width : key_width + 1], key_width),
            _raw_field("record_identity", identity_raw, identity_offset),
            _raw_field(
                "receiver_ignored_trailing",
                parsed.ignored_trailing_raw,
                identity_offset + identity_length,
            ),
        )
    )

    if parsed.type_byte == NID_TYPE:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "swf_scan_nid@0x180A5BF1C"),
                        ("query_selector", 6),
                        ("key_source", "context DWORDs at +0x60, +0x64, +0x68"),
                        ("operation", "caller passes each present DWORD unchanged"),
                        ("upstream_producer", "unknown"),
                    )
                ),
            )
        )
    elif parsed.type_byte == SNID_TYPE:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "scan_imphash@0x1804A6370"),
                        ("query_selector", 98),
                        (
                            "key_source",
                            "context +0xAA018 (16 bytes) || context +0xAA028 (4 bytes)",
                        ),
                        ("operation", "copied unchanged to snidsearchrecidex"),
                        ("upstream_producer", "unknown"),
                    )
                ),
            )
        )
    else:
        provider_inputs = JSONArray(
            (
                JSONObject(
                    (
                        ("caller", "IsHighlyTrustedPublisher@0x1805179D8"),
                        ("query_selector", 132),
                        ("key_source", "sigseqfromrecid(recid)"),
                        ("operation", "existing signature sequence passed as uint64"),
                    )
                ),
                JSONObject(
                    (
                        ("caller", "CheckPublisher@0x180298E3C"),
                        ("query_selector", 133),
                        (
                            "key_source",
                            "SCAN_REPLY +0x90 after trustedpublisher lookup",
                        ),
                        ("operation", "existing QWORD passed as uint64"),
                    )
                ),
            )
        )

    issues: list[SemanticIssue] = [
        SemanticIssue(
            "upstream_key_generation_unknown",
            "Provider-level caller inputs are recorded per family, but upstream "
            "generation remains unknown: NID/SNID context-field producers are "
            "unlocated; NID64 accepts RecID signature-sequence or existing reply "
            "QWORD sources without establishing their common derivation.",
        ),
        SemanticIssue(
            "outer_verdict_unknown",
            "A successful table lookup is not exported as a final detection verdict.",
        ),
    ]
    unsupported = False
    if parsed.identity_kind == "raw":
        unsupported = True
        issues.append(
            SemanticIssue(
                "unknown_identity_kind",
                "The record identity bytes have no confirmed receiver semantics.",
            )
        )
    if parsed.ignored_trailing_raw:
        unsupported = True
        issues.append(
            SemanticIssue(
                "receiver_ignored_trailing",
                "Bytes after the bounded record identity are ignored by the receiver.",
                (("length", len(parsed.ignored_trailing_raw)),),
            )
        )

    return RuleSemantics(
        status="unsupported" if unsupported else "confirmed_subset",
        representation="nid.exact_lookup.ir.v2",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                ("framing", framing),
                ("type_byte", parsed.type_byte),
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("key_width", key_width),
                (
                    "metadata_source",
                    JSONObject(
                        (
                            ("wire_payload_offset", key_width),
                            ("raw_value", parsed.metadata_raw),
                            (
                                "lookup_role",
                                "compared exactly with provider query_selector",
                            ),
                            ("normalization", "none confirmed at receiver/lookup"),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "exact"),
                            ("key_raw_hex", parsed.key_raw.hex()),
                            ("metadata_raw", parsed.metadata_raw),
                        )
                    ),
                ),
                ("provider_specific_key_inputs_confirmed_subset", provider_inputs),
                (
                    "record_identity",
                    JSONObject(
                        (
                            ("kind", parsed.identity_kind),
                            ("raw_hex", identity_raw.hex()),
                        )
                    ),
                ),
                (
                    "receiver_ignored_trailing_raw_hex",
                    parsed.ignored_trailing_raw.hex(),
                ),
            )
        ),
        evidence=(
            (
                "NID-family exact lookup wrappers: nidsearchrecidex@0x1800B01B0, "
                "snidsearchrecidex@0x180145618, nid64searchrecid@0x1800AE690"
            ),
            (
                "provider callers: swf_scan_nid@0x180A5BF1C, "
                "scan_imphash@0x1804A6370, IsHighlyTrustedPublisher@0x1805179D8, "
                "CheckPublisher@0x180298E3C"
            ),
            (
                "receiver wire fields: NID RecordPush@0x180447AE4, "
                "SNID RecordPush@0x1800FA5F0, NID64 RecordPush@0x180497874"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


def export_nid_artifact(parsed: NidPayload) -> ArtifactExport:
    """Export the exact-key record and all following bytes losslessly."""
    key_width = _KEY_WIDTHS[parsed.type_byte]
    manifest = {
        "schema": "vdm.nid.artifact.v1",
        "record_type": {
            "byte": parsed.type_byte,
            "name": _FAMILY_NAMES[parsed.type_byte],
        },
        "raw_hex": parsed.raw.hex(),
        "key": {"offset": 0, "length": key_width, "raw_hex": parsed.key_raw.hex()},
        "metadata": {
            "offset": key_width,
            "raw_hex": parsed.raw[key_width : key_width + 1].hex(),
            "value": parsed.metadata_raw,
        },
        "recid_input": {
            "offset": key_width + 1,
            "raw_hex": parsed.recid_input_raw.hex(),
            "receiver_identity_kind": parsed.identity_kind,
            "bounded_object_raw_hex": (
                None if parsed.object_raw is None else parsed.object_raw.hex()
            ),
            "receiver_ignored_trailing_raw_hex": parsed.ignored_trailing_raw.hex(),
        },
        "matcher_boundary": {
            "confirmed_operation": "exact_key_and_metadata_byte_lookup",
            "key_generation": "unknown",
            "provider_selector": "unknown",
            "recid_or_pcode_effect": "unknown",
            "final_report_or_verdict": "unknown",
        },
    }
    data = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(parsed.raw).hexdigest()[:16]
    return ArtifactExport(
        "ready",
        artifacts=(
            Artifact(
                f"{parsed.type_byte:02x}-{digest}.json", "nid_json_manifest", data
            ),
        ),
    )


def _parser_for(type_byte: int) -> Callable[[bytes], NidPayload]:
    def parser(payload: bytes) -> NidPayload:
        return parse_nid(payload, type_byte=type_byte)

    return parser


NID_SPECS = tuple(
    FamilySpec(
        type_byte,
        name,
        _parser_for(type_byte),
        render_nid,
        exporter=export_nid_artifact,
        semantic_exporter=export_nid_semantics,
    )
    for type_byte, name in _FAMILY_NAMES.items()
)
