from dataclasses import dataclass

from ..core import (
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticUnknown,
)

_DETECTION_FLAG_BITS = (
    (0x01, "low", 0x00000080),
    (0x02, "low", 0x00000100),
    (0x04, "low", 0x00000200),
    (0x08, "low", 0x00000400),
    (0x10, "low", 0x00000800),
    (0x20, "low", 0x00400000),
    (0x40, "low", 0x00800000),
    (0x80, "high", 0x00000010),
)

# Verified against mpengine.dll 1.443.903.0 BmDetectionDetails::ParseAction.
# The engine compares names case-insensitively and returns zero for unknown names.
_ACTION_TOKEN_MASKS = {
    "eventlog": 0x0000000000000001,
    "telemetry": 0x0000000000000002,
    "ui": 0x0000000000000004,
    "remediateprocess": 0x0000000000000008,
    "remediatebasefile": 0x0000000000000010,
    "alwayssendsamples": 0x0000000000000020,
    "sendmodules": 0x0000000000000040,
    "singleprocessscan": 0x0000000000000080,
    "allprocessscan": 0x0000000000000100,
    "emsscan": 0x0000000000001000,
    "regkeyvaluescan": 0x0000000000004000,
    "turnnrion": 0x0000000000010000,
    "bootscan": 0x0000000000020000,
    "driverscan": 0x0000000000040000,
    "wmiscan": 0x0000000000080000,
    "fastremediation": 0x0000000000100000,
    "remediatemultiprocess": 0x0000000000200000,
    "informcamp": 0x0000000000800000,
    "monitoreop": 0x0000000001000000,
    "monitorproctreeeop": 0x0000000002000000,
    "setprocesstainted": 0x0000000004000000,
    "smsscan": 0x0000000008000000,
    "fdrprocess": 0x0000000010000000,
    "fdrfile": 0x0000000020000000,
    "parentinfo": 0x0000000040000000,
    "smsasyncscanevent": 0x0000000080000000,
    "emsmappedscan": 0x0000000100000000,
    "senseetw": 0x0000000200000000,
    "bootbackup": 0x0000000400000000,
    "bootrestore": 0x0000000800000000,
    "memoryquery": 0x0000001000000000,
}

_POLICY_MASK_OBSERVED_EFFECTS = (
    (
        0x0100,
        (
            "ReportDetection:skip_cache_suppression_gate",
            "IsExpensiveOperationAllowed:skip_throttle_and_allow",
        ),
    ),
    (
        0x0200,
        (
            "ReportDetection:related_pid_lookup_and_reset_detection",
            "IsExpensiveOperationAllowed:deny",
        ),
    ),
    (
        0x0400,
        (
            "ReportDetection:pass_true_to_ProcessAdditionalActions",
            "ReportDetection:suppress_PerformDetectionActions",
            "ReportDetection:set_descriptor_flag_bit_2",
        ),
    ),
    (0x0800, ("ReportDetection:set_descriptor_flag_bit_3",)),
)


@dataclass(frozen=True, slots=True)
class BMInfo:
    """Lossless parsed fields for a BM_INFO (0xA8) payload."""

    raw: bytes
    blob_len: int
    blob: bytes
    friendly_filter_mask: int
    fidelity_raw: bytes
    actions_raw: bytes
    action_tokens: tuple[str, ...]
    trailing_raw: bytes

    @property
    def receiver_accepted(self) -> bool:
        return self.friendly_filter_mask < 0x1000

    @property
    def recid_object_raw(self) -> bytes | None:
        """Opaque payload+2 span interned only on the nonempty-blob path."""
        candidate = self.raw[2:]
        return candidate if self.blob_len and candidate and candidate[0] else None

    @property
    def detection_flags(self) -> tuple[int, int]:
        low = 0
        high = 0
        for mask, half, value in _DETECTION_FLAG_BITS:
            if self.friendly_filter_mask & mask:
                if half == "low":
                    low |= value
                else:
                    high |= value
        return low, high


def parse_bm_info(payload: bytes) -> BMInfo:
    """Parse BM_INFO's length-prefixed blob and NUL-terminated strings."""
    if len(payload) < 2:
        raise ValueError("truncated blob_len")

    blob_len = int.from_bytes(payload[0:2], "little")
    cursor = 2
    end = cursor + blob_len
    if end > len(payload):
        raise ValueError("truncated blob")
    blob = payload[cursor:end]
    cursor = end

    if cursor + 2 > len(payload):
        raise ValueError("truncated friendly_filter_mask")
    friendly_filter_mask = int.from_bytes(payload[cursor : cursor + 2], "little")
    cursor += 2

    def read_string(label: str) -> bytes:
        nonlocal cursor
        if cursor + 2 > len(payload):
            raise ValueError(f"truncated {label}_len")
        size = int.from_bytes(payload[cursor : cursor + 2], "little")
        cursor += 2
        end = cursor + size
        if end > len(payload):
            raise ValueError(f"truncated {label}")
        value = payload[cursor:end]
        cursor = end
        if not value:
            raise ValueError(f"{label} must include a terminating NUL")
        if value[-1] != 0:
            raise ValueError(f"{label} is missing terminating NUL")
        return value

    fidelity_raw = read_string("fidelity")
    actions_raw = read_string("actions")
    action_data = actions_raw[:-1]
    action_tokens = (
        tuple(token.decode("latin-1") for token in action_data.split(b"+"))
        if action_data
        else ()
    )

    return BMInfo(
        raw=payload,
        blob_len=blob_len,
        blob=blob,
        friendly_filter_mask=friendly_filter_mask,
        fidelity_raw=fidelity_raw,
        actions_raw=actions_raw,
        action_tokens=action_tokens,
        trailing_raw=payload[cursor:],
    )


def render_bm_info(info: BMInfo) -> FormatResult:
    """Render known fields while retaining byte-exact raw representations."""
    detection_low, detection_high = info.detection_flags
    return FormatResult(
        fields=(
            ("blob_len", str(info.blob_len)),
            ("blob_raw", info.blob.hex(" ") or "(empty)"),
            (
                "recid_object_span",
                (
                    f"{len(info.recid_object_raw)} B from payload+2 (opaque)"
                    if info.recid_object_raw is not None
                    else "not created"
                ),
            ),
            ("friendly_filter_mask", f"{info.friendly_filter_mask:#06x}"),
            (
                "receiver_status",
                "accepted" if info.receiver_accepted else "rejected: mask >= 0x1000",
            ),
            (
                "detection_flags",
                f"low32=0x{detection_low:08x}, high32=0x{detection_high:08x}",
            ),
            (
                "unresolved_mask_bits",
                f"0x{info.friendly_filter_mask & 0x0F00:04x}",
            ),
            ("fidelity_len", str(len(info.fidelity_raw))),
            ("fidelity_raw", info.fidelity_raw.hex(" ")),
            ("fidelity", info.fidelity_raw[:-1].decode("latin-1")),
            ("actions_len", str(len(info.actions_raw))),
            ("actions_raw", info.actions_raw.hex(" ")),
            (
                "action_tokens",
                " | ".join(info.action_tokens) or "(empty)",
            ),
            ("trailing_raw", info.trailing_raw.hex(" ") or "(empty)"),
            (
                "trailing_behavior",
                "accepted; included in full-payload CRC/SHA-1"
                + (
                    " and RecID object span"
                    if info.recid_object_raw is not None
                    else ""
                ),
            ),
        )
    )


def _wire_field(kind: str, raw: bytes, offset: int) -> JSONObject:
    return JSONObject(
        (
            ("kind", kind),
            ("raw_span", JSONObject((("offset", offset), ("length", len(raw))))),
            ("raw_hex", raw.hex()),
        )
    )


def _parse_fidelity_prefix(
    raw: bytes,
) -> tuple[int | None, list[JSONObject], list[str]]:
    text = raw.split(b"\0", 1)[0]
    issues: list[str] = []
    if len(text) != len(raw) - 1:
        issues.append("fidelity contains bytes after its first NUL")
    if not text.isascii():
        return None, [], [*issues, "fidelity contains non-ASCII bytes"]
    parts = text.split(b",")
    if not parts or not parts[0].isdigit():
        return None, [], [*issues, "base fidelity is not a decimal integer"]
    base_score = int(parts[0])
    if base_score >= 100:
        issues.append("base fidelity is outside the confirmed 0..99 range")
    enhancers: list[JSONObject] = []
    sources_with_nonzero_fidelity: set[str] = set()
    for part in parts[1:]:
        score_raw, separator, source_raw = part.partition(b"+")
        source = source_raw.decode("ascii", errors="replace")
        known_source = source.lower() in {"packed", "system32"}
        if not separator or not score_raw.isdigit() or not known_source:
            issues.append("enhancer token is outside the confirmed score+source form")
            enhancers.append(
                JSONObject(
                    (("raw_hex", part.hex()), ("source", None), ("fidelity", None))
                )
            )
            continue
        score = int(score_raw)
        if score > 0xFFFF:
            issues.append("enhancer fidelity is outside the confirmed U16 range")
            enhancers.append(
                JSONObject(
                    (("raw_hex", part.hex()), ("source", None), ("fidelity", None))
                )
            )
            continue
        canonical_source = "Packed" if source.lower() == "packed" else "System32"
        appended = score != 0 and canonical_source not in sources_with_nonzero_fidelity
        if appended:
            sources_with_nonzero_fidelity.add(canonical_source)
        enhancers.append(
            JSONObject(
                (
                    ("raw_hex", part.hex()),
                    ("source", canonical_source),
                    ("fidelity", score),
                    ("appended", appended),
                )
            )
        )
    return base_score, enhancers, issues


def _parse_action_entries(raw: bytes) -> tuple[list[JSONObject], list[str]]:
    text = raw.split(b"\0", 1)[0]
    issues: list[str] = []
    if len(text) != len(raw) - 1:
        issues.append("actions contains bytes after its first NUL")
    if not text:
        return [], issues
    if not text.isascii():
        return [], [*issues, "actions contains non-ASCII bytes"]
    entries: list[JSONObject] = []
    for entry in text.split(b","):
        severity_raw, separator, actions_raw = entry.partition(b":")
        actions = actions_raw.split(b"+") if separator else []
        severity = severity_raw.decode("ascii")
        severity_canonical = {
            "low": "Low",
            "medium": "Medium",
            "high": "High",
        }.get(severity.lower())
        if (
            not separator
            or severity_canonical is None
            or not actions
            or any(not action for action in actions)
        ):
            issues.append("action entry is outside the confirmed severity/action form")
        token_masks = tuple(
            _ACTION_TOKEN_MASKS.get(action.decode("ascii").lower(), 0)
            for action in actions
        )
        unknown_tokens = tuple(
            action.decode("ascii")
            for action, mask in zip(actions, token_masks, strict=True)
            if mask == 0
        )
        entries.append(
            JSONObject(
                (
                    (
                        "severity",
                        severity_canonical,
                    ),
                    (
                        "action_tokens",
                        JSONArray(tuple(action.decode("ascii") for action in actions)),
                    ),
                    ("token_masks", JSONArray(token_masks)),
                    ("action_mask", _or_masks(token_masks)),
                    ("unknown_action_tokens", JSONArray(unknown_tokens)),
                    ("raw_hex", entry.hex()),
                )
            )
        )
    return entries, issues


def _or_masks(masks: tuple[int, ...]) -> int:
    result = 0
    for mask in masks:
        result |= mask
    return result


def export_bm_info_semantics(info: BMInfo) -> RuleSemantics:
    """Export receiver, filter, fidelity, and action-routing evidence losslessly."""
    blob_len_offset = 0
    blob_offset = 2
    mask_offset = blob_offset + info.blob_len
    fidelity_length_offset = mask_offset + 2
    fidelity_offset = fidelity_length_offset + 2
    actions_length_offset = fidelity_offset + len(info.fidelity_raw)
    actions_offset = actions_length_offset + 2
    trailing_offset = actions_offset + len(info.actions_raw)

    base_score, enhancers, fidelity_parse_issues = _parse_fidelity_prefix(
        info.fidelity_raw
    )
    action_entries, action_parse_issues = _parse_action_entries(info.actions_raw)
    low_flags, high_flags = info.detection_flags
    policy_mask_bits = info.friendly_filter_mask & 0x0F00
    observed_policy_mask_effects = JSONArray(
        tuple(
            JSONObject(
                (
                    ("policy_bit", f"policy_bit_{bit:#06x}"),
                    ("bit", bit),
                    ("observed_effects", JSONArray(effects)),
                    ("complete_semantics", False),
                )
            )
            for bit, effects in _POLICY_MASK_OBSERVED_EFFECTS
            if policy_mask_bits & bit
        )
    )
    issues = [
        SemanticIssue(
            "enhancer_consumers_incomplete",
            "Enhancer parsing and vector insertion are confirmed, but other runtime "
            "consumers are not.",
        ),
    ]
    if policy_mask_bits:
        issues.append(
            SemanticIssue(
                "friendly_filter_policy_incomplete",
                "The mask is stored as BmDetectionDetails policy state. Bits "
                "8 through 11 have observed direct effects in the listed "
                "consumers, but their formal names and complete cross-consumer "
                "policy or verdict semantics remain unknown. The mask bytes "
                "also participate in payload identity; that does not make the "
                "mask identity-only metadata.",
                (("value", policy_mask_bits),),
            )
        )
    if info.blob_len:
        issues.append(
            SemanticIssue(
                "identity_blob_generator_and_subformat_unknown",
                "On the nonzero-first-byte path, the engine interns payload+2 and "
                "includes the result in the outer RecID. The external signature "
                "generator, blob subformat, and any independent child consumer are unknown.",
                (("blob_length", info.blob_len),),
            )
        )
    if info.trailing_raw:
        issues.append(
            SemanticIssue(
                "trailing_bytes_semantics_unknown",
                "Trailing bytes are accepted and included in payload identity, but "
                "are not parsed as fields.",
                (("length", len(info.trailing_raw)),),
            )
        )
    if fidelity_parse_issues:
        issues.extend(
            SemanticIssue("fidelity_value_unresolved", message)
            for message in fidelity_parse_issues
        )
    if action_parse_issues:
        issues.extend(
            SemanticIssue("action_value_unresolved", message)
            for message in action_parse_issues
        )

    status = (
        "unsupported"
        if (
            not info.receiver_accepted
            or info.blob_len
            or info.trailing_raw
            or fidelity_parse_issues
            or action_parse_issues
        )
        else "confirmed_subset"
    )
    selected_severity = (
        None
        if base_score is None or base_score >= 100
        else "Low"
        if 1 <= base_score <= 33
        else "Medium"
        if 34 <= base_score <= 66
        else "High"
    )
    recid_object = info.recid_object_raw
    return RuleSemantics(
        status=status,
        representation="bm_info.receiver-policy.ir.v3",
        data=JSONObject(
            (
                ("type", "BM_INFO"),
                ("raw_hex", info.raw.hex()),
                (
                    "blob_length",
                    _wire_field("blob_length", info.raw[:2], blob_len_offset),
                ),
                ("blob", _wire_field("opaque_blob", info.blob, blob_offset)),
                (
                    "friendly_filter_mask",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "friendly_filter_mask",
                                    info.raw[mask_offset : mask_offset + 2],
                                    mask_offset,
                                ),
                            ),
                            ("value", info.friendly_filter_mask),
                            ("receiver_accepted", info.receiver_accepted),
                            (
                                "detection_flags",
                                JSONObject(
                                    (
                                        ("low32", low_flags),
                                        ("high32", high_flags),
                                    )
                                ),
                            ),
                            ("policy_bits_8_11", policy_mask_bits),
                            (
                                "observed_policy_bits_8_11_effects",
                                observed_policy_mask_effects,
                            ),
                        )
                    ),
                ),
                (
                    "fidelity",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "fidelity_text",
                                    info.fidelity_raw,
                                    fidelity_offset,
                                ),
                            ),
                            ("base_score", base_score),
                            ("report_mask_severity", selected_severity),
                            ("enhancers", JSONArray(tuple(enhancers))),
                        )
                    ),
                ),
                (
                    "actions",
                    JSONObject(
                        (
                            (
                                "wire",
                                _wire_field(
                                    "actions_text", info.actions_raw, actions_offset
                                ),
                            ),
                            ("entries", JSONArray(tuple(action_entries))),
                        )
                    ),
                ),
                (
                    "record_identity",
                    JSONObject(
                        (
                            (
                                "crc_sha1_input",
                                _wire_field("complete_payload", info.raw, 0),
                            ),
                            (
                                "recid_object_span",
                                None
                                if recid_object is None
                                else _wire_field("payload_plus_2", recid_object, 2),
                            ),
                            ("object_interned", recid_object is not None),
                            (
                                "outer_recid_inclusion",
                                (
                                    "createrecidfrombuffex -> kpushobject -> "
                                    "createrecid"
                                    if recid_object is not None
                                    else "not_applicable"
                                ),
                            ),
                            (
                                "external_signature_generator",
                                "unknown" if info.blob_len else "not_applicable",
                            ),
                            (
                                "blob_subformat",
                                "unknown" if info.blob_len else "not_applicable",
                            ),
                            (
                                "independent_child_object_consumer",
                                "unknown"
                                if recid_object is not None
                                else "not_applicable",
                            ),
                        )
                    ),
                ),
                (
                    "trailing",
                    _wire_field("trailing", info.trailing_raw, trailing_offset),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 BMDetectionReceiver bounded fields and identity",
            (
                "mpengine 1.443.903.0 BMDetectionReceiver @ 0x1802A6610 -> "
                "createrecidfrombuffex @ 0x1804706E0 -> createrecid @ 0x1800FB5EC"
            ),
            "mpengine 1.443.903.0 ProcessFriendlyFiltering validation and mask storage",
            "mpengine 1.443.903.0 GetDetectionFlags low-eight-bit mapping",
            (
                "mpengine 1.443.903.0 SignatureHandler::ReportDetection @ "
                "0x1802A314C: policy bits 8-11 local branches"
            ),
            (
                "mpengine 1.443.903.0 BmController::IsExpensiveOperationAllowed @ "
                "0x180B75118: policy bits 8-9 gate"
            ),
            "mpengine 1.443.903.0 ExtractFidelity and GetFidelityEnhancers",
            "mpengine 1.443.903.0 ProcessDetectionActions and action-list parsing",
            (
                "mpengine 1.443.903.0 BmDetectionDetails::ParseAction @ "
                "0x1802A7348: case-insensitive action-token masks"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
        claims=(
            SemanticClaim(
                "bm-info-wire",
                "wire_layout",
                "BM_INFO carries a length-prefixed blob, friendly filter mask, NUL-terminated fidelity and actions strings, and accepted trailing bytes.",
                "subset",
                ("bm-info-receiver",),
                (
                    SemanticUnknown(
                        "wire_layout",
                        "Blob subformat and trailing byte fields are unknown.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-info-policy",
                "runtime_consumer",
                "Selected friendly-filter mask bits have observed local effects in report and throttling consumers.",
                "subset",
                ("bm-info-policy-evidence",),
                (
                    SemanticUnknown(
                        "runtime_consumer",
                        "Formal bit names and complete policy semantics are not established.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-info-report-admission",
                "report_mapping",
                "Friendly-filter bit 0x0200 can suppress queue admission near the pending-item limit and can reject DetectionItem::Send before dispatcher reporting for selected action flags.",
                "subset",
                ("bm-info-report-admission-evidence",),
                (
                    SemanticUnknown(
                        "report_mapping",
                        "The remaining mask bits, concrete registered handler outcome, and host-visible result are not closed.",
                    ),
                ),
            ),
            SemanticClaim(
                "bm-info-verdict",
                "final_verdict",
                "BM_INFO alone does not establish a final verdict.",
                "unknown",
                (),
                (
                    SemanticUnknown(
                        "final_verdict",
                        "Final report outcome depends on broader runtime policy.",
                    ),
                ),
            ),
        ),
        claim_evidence=(
            SemanticEvidence(
                "bm-info-receiver",
                "wire_parser",
                "engine_static",
                "BMDetectionReceiver 0x1802A6610",
                ("bm-info-wire",),
            ),
            SemanticEvidence(
                "bm-info-policy-evidence",
                "consumer",
                "engine_static",
                "ProcessFriendlyFiltering; ReportDetection; IsExpensiveOperationAllowed",
                ("bm-info-policy",),
            ),
            SemanticEvidence(
                "bm-info-report-admission-evidence",
                "report",
                "engine_static",
                "mpengine 1.443.903.0",
                ("bm-info-report-admission",),
                "DetectionQueue::QueueDetection @ 0x1803911F4; DetectionItem::Send @ 0x18057BB7C",
            ),
        ),
    )


SPEC = FamilySpec(
    0xA8,
    "BM_INFO",
    parse_bm_info,
    render_bm_info,
    semantic_exporter=export_bm_info_semantics,
)
