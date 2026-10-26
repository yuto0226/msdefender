from dataclasses import dataclass

from ..core import (
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)
from ._semantic_claims import scoped_claim

_HEADER_SIZE = 32
_VERSION_MAJOR = 1


@dataclass(frozen=True, slots=True)
class CleanScriptPayload:
    raw: bytes
    discriminator: int
    version_flags: int
    value_4: int
    value_8: int
    length_0: int
    length_1: int
    length_2: int
    count_3: int
    byte_18: int
    byte_19: int
    reserved_raw: bytes
    tail_raw: bytes
    expected_tail_len: int
    receiver_result: str


def _tail_length(parsed_fields: tuple[int, int, int, int]) -> int:
    length_0, length_1, length_2, count_3 = parsed_fields
    size = length_0 + length_1 + length_2 + 3 * count_3
    if (length_2 - count_3) & 1 == 0:
        size += 1
    return size


def parse_cleanscript(payload: bytes) -> CleanScriptPayload:
    if len(payload) < _HEADER_SIZE:
        raise ValueError("truncated CLEANSCRIPT header")
    if len(payload) == _HEADER_SIZE:
        raise ValueError("CLEANSCRIPT payload must exceed 32 B")

    discriminator = int.from_bytes(payload[0:2], "little")
    version_flags = int.from_bytes(payload[2:4], "little")
    value_4 = int.from_bytes(payload[4:8], "little")
    value_8 = int.from_bytes(payload[8:12], "little")
    length_0 = int.from_bytes(payload[12:14], "little")
    length_1 = int.from_bytes(payload[14:16], "little")
    length_2 = payload[16]
    count_3 = payload[17]
    byte_18, byte_19 = payload[18:20]
    reserved_raw = payload[20:32]

    version_major = version_flags >> 8
    version_minor = version_flags & 0xFF
    is_candidate = (
        discriminator < 4 and version_major == _VERSION_MAJOR and version_minor <= 1
    )
    expected_tail_len = _tail_length((length_0, length_1, length_2, count_3))
    tail_raw = payload[_HEADER_SIZE:]

    if discriminator >= 4:
        receiver_result = "no_op.discriminator_ge_4"
    elif not is_candidate:
        receiver_result = "no_op.unsupported_version_flags"
    else:
        if len(tail_raw) != expected_tail_len:
            raise ValueError(
                "CLEANSCRIPT tail size mismatch: "
                f"expected {expected_tail_len} B, got {len(tail_raw)} B"
            )
        receiver_result = "added_candidate"

    return CleanScriptPayload(
        raw=payload,
        discriminator=discriminator,
        version_flags=version_flags,
        value_4=value_4,
        value_8=value_8,
        length_0=length_0,
        length_1=length_1,
        length_2=length_2,
        count_3=count_3,
        byte_18=byte_18,
        byte_19=byte_19,
        reserved_raw=reserved_raw,
        tail_raw=tail_raw,
        expected_tail_len=expected_tail_len,
        receiver_result=receiver_result,
    )


def render_cleanscript(parsed: CleanScriptPayload) -> FormatResult:
    def preview(raw: bytes) -> str:
        shown = raw[:32].hex(" ")
        suffix = " …" if len(raw) > 32 else ""
        return f"{len(raw)} B [{shown}{suffix}]" if raw else "(empty)"

    return FormatResult(
        fields=(
            ("receiver_result", parsed.receiver_result),
            ("discriminator", str(parsed.discriminator)),
            ("version_flags", f"{parsed.version_flags:#06x}"),
            ("value_4", f"{parsed.value_4:#010x}"),
            ("value_8", f"{parsed.value_8:#010x}"),
            ("length_0", str(parsed.length_0)),
            ("length_1", str(parsed.length_1)),
            ("length_2", str(parsed.length_2)),
            ("count_3", str(parsed.count_3)),
            ("byte_18", f"{parsed.byte_18:#04x}"),
            ("byte_19", f"{parsed.byte_19:#04x}"),
            ("reserved_raw", preview(parsed.reserved_raw)),
            ("expected_tail_len", f"{parsed.expected_tail_len} B"),
            ("tail_len", f"{len(parsed.tail_raw)} B"),
            ("tail_raw", preview(parsed.tail_raw)),
        )
    )


def export_cleanscript_semantics(parsed: CleanScriptPayload) -> RuleSemantics:
    """Export confirmed receiver/runtime-selection facts, keeping other fields raw."""
    claim, claim_evidence = scoped_claim(
        "cleanscript",
        "receiver_handoff",
        "receiver_transform",
        "The receiver accepts bounded versioned payloads and hands accepted candidates to the interpreter path.",
        "Opcode interpretation and any final verdict are unknown.",
        "receiver",
        "CLEANSCRIPT receiver and pInterpretRoutine handoff",
    )
    accepted = parsed.receiver_result == "added_candidate"
    status = "confirmed_subset" if accepted else "ignored"
    issues = (
        (
            SemanticIssue(
                "cleanscript_field_semantics_unknown",
                "The runtime consumer confirms the discriminator, routine arity, "
                "mode mask, and conditional identifier comparisons. Other wire "
                "fields remain offset-based because their runtime roles are not "
                "confirmed.",
            ),
        )
        if accepted
        else (
            SemanticIssue(
                "receiver_ignored_candidate",
                "The current receiver returns success without adding this payload "
                "to the CLEANSCRIPT candidate table.",
                details=(("receiver_result", parsed.receiver_result),),
            ),
        )
    )
    return RuleSemantics(
        status=status,
        representation="cleanscript.receiver_candidate_and_consumer.v2",
        data=JSONObject(
            (
                ("type", "CLEANSCRIPT"),
                ("raw_hex", parsed.raw.hex()),
                (
                    "wire_fields",
                    JSONObject(
                        (
                            ("discriminator", parsed.discriminator),
                            ("version_flags", parsed.version_flags),
                            ("value_4", parsed.value_4),
                            ("value_8", parsed.value_8),
                            ("length_0", parsed.length_0),
                            ("length_1", parsed.length_1),
                            ("length_2", parsed.length_2),
                            ("count_3", parsed.count_3),
                            ("byte_18", parsed.byte_18),
                            ("byte_19", parsed.byte_19),
                            ("reserved_raw_hex", parsed.reserved_raw.hex()),
                            ("tail_raw_hex", parsed.tail_raw.hex()),
                        )
                    ),
                ),
                (
                    "receiver_candidate",
                    JSONObject(
                        (
                            ("receiver", "sysclean_push"),
                            ("receiver_address", "0x180562F00"),
                            ("candidate_added", accepted),
                            ("receiver_result", parsed.receiver_result),
                            ("discriminator_range", "0..3"),
                            ("version_major", 1),
                            ("version_minor_max", 1),
                            ("tail_length_expected", parsed.expected_tail_len),
                            ("tail_length_observed", len(parsed.tail_raw)),
                        )
                    ),
                ),
                (
                    "confirmed_consumers",
                    JSONObject(
                        (
                            ("runtime_table_consumer", "sysclean"),
                            ("runtime_table_consumer_address", "0x180555DBC"),
                            (
                                "dispatch_targets",
                                JSONArray(
                                    ("pInterpretRoutine", "pInterpretOnEachDetection")
                                ),
                            ),
                            ("interpreter_body", "pInterpretBody"),
                            ("script_role", "cleanup routine data"),
                            ("detection_rule", False),
                        )
                    ),
                ),
                (
                    "runtime_selection",
                    JSONObject(
                        (
                            (
                                "discriminator_role",
                                "caller_mode_mask_bit_index_and_callback_slot",
                            ),
                            (
                                "callback_by_discriminator",
                                JSONObject(
                                    (
                                        (
                                            "0",
                                            JSONObject(
                                                (
                                                    ("callback", "pInterpretRoutine"),
                                                    ("variant_count", 0),
                                                )
                                            ),
                                        ),
                                        ("1", None),
                                        ("2", None),
                                        (
                                            "3",
                                            JSONObject(
                                                (
                                                    (
                                                        "callback",
                                                        "pInterpretOnEachDetection",
                                                    ),
                                                    ("variant_count", 1),
                                                    ("variant_type", 512),
                                                )
                                            ),
                                        ),
                                    )
                                ),
                            ),
                            (
                                "routine_variant_count",
                                JSONObject(
                                    (
                                        ("wire_offset", 16),
                                        ("comparison", "equals_callback_variant_count"),
                                    )
                                ),
                            ),
                            (
                                "mode_mask",
                                JSONObject(
                                    (
                                        ("wire_offset", 19),
                                        ("handle_offset", 49),
                                        ("predicate", "bitwise_and_nonzero"),
                                    )
                                ),
                            ),
                            (
                                "conditional_comparison",
                                JSONObject(
                                    (
                                        (
                                            "primary",
                                            JSONObject(
                                                (
                                                    ("when_handle_offset", 24),
                                                    ("when", "nonzero"),
                                                    ("left_wire_offset", 4),
                                                    (
                                                        "left_normalization",
                                                        "sentinel_to_0xFFFFFFFF",
                                                    ),
                                                    ("operator", "equals"),
                                                    ("right_handle_offset", 24),
                                                )
                                            ),
                                        ),
                                        (
                                            "fallback",
                                            JSONObject(
                                                (
                                                    ("when_handle_offset", 28),
                                                    (
                                                        "when",
                                                        "primary_is_zero_and_fallback_nonzero",
                                                    ),
                                                    ("left", "receiver_arg4"),
                                                    ("operator", "equals"),
                                                    ("right_handle_offset", 28),
                                                )
                                            ),
                                        ),
                                        (
                                            "both_zero",
                                            "skip_identifier_comparison",
                                        ),
                                    )
                                ),
                            ),
                            (
                                "callback_absent_behavior",
                                "no callback invocation; candidate scan continues",
                            ),
                            (
                                "row_sort_keys",
                                (
                                    "callback-table priority, row DWORD +0x08, "
                                    "then row DWORD +0x10"
                                ),
                            ),
                        )
                    ),
                ),
                (
                    "field_semantics",
                    (
                        "confirmed runtime roles are listed above; all remaining "
                        "fields retain offset/raw names"
                    ),
                ),
            )
        ),
        evidence=(
            "mpengine 1.443.903.0 sysclean_init_module @ 0x1805FB970",
            "mpengine 1.443.903.0 sysclean_push @ 0x180562F00",
            "mpengine 1.443.903.0 sysclean @ 0x180555DBC",
            (
                "mpengine 1.443.903.0 pInterpretRoutine @ 0x180AAE790 and "
                "pInterpretOnEachDetection @ 0x180AAE710"
            ),
            "mpengine 1.443.903.0 runtime callback table at 0x180E47A60",
        ),
        profile="mpengine-1.443.903.0",
        issues=issues,
        claims=(claim,),
        claim_evidence=(claim_evidence,),
    )


SPEC = FamilySpec(
    0x49,
    "CLEANSCRIPT",
    parse_cleanscript,
    render_cleanscript,
    semantic_exporter=export_cleanscript_semantics,
)
