"""Lossless AAGGREGATOR envelopes, verified against mpengine 1.443.903.0."""

from dataclasses import dataclass
from functools import partial
from typing import Final, Literal

from ..condition import And, Atom, Expr, Not, Or, render_yara_like
from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticClaim,
    SemanticEvidence,
    SemanticIssue,
    SemanticJSONValue,
    SemanticUnknown,
)
from ..pattern_codec import PATTERN_DECODING_TABLE

AAGGREGATOR_TYPE: Final = 0x96
AAGGREGATOREX_TYPE: Final = 0xE7
_FAMILY_NAMES: Final = {
    AAGGREGATOR_TYPE: "AAGGREGATOR",
    AAGGREGATOREX_TYPE: "AAGGREGATOREX",
}


@dataclass(frozen=True, slots=True)
class AggregatorPayload:
    """Wire bytes and byte decoding, without claiming expression semantics.

    Unknown flag bits cause an early successful skip in both receivers, before
    length validation. Such records retain available body slices even if their
    declared lengths exceed the payload; decoded_sig_data is then unavailable.
    """

    raw: bytes
    type_byte: int
    flags: int
    name_len: int
    sig_len: int
    name: bytes
    sig_data: bytes
    trailing: bytes
    decoded_sig_data: bytes | None

    @property
    def fuzzy(self) -> bool:
        return bool(self.flags & 1)

    @property
    def unknown_flag_bits(self) -> int:
        return self.flags & 0xFE

    @property
    def receiver_ignored(self) -> bool:
        return bool(self.unknown_flag_bits)

    @property
    def body_complete(self) -> bool:
        return 4 + self.name_len + self.sig_len <= len(self.raw)


AggregatorIssueCode = Literal[
    "receiver_ignored",
    "source_marker",
    "empty_expression",
    "empty_operand",
    "unbalanced_parentheses",
    "operand_too_long",
    "unexpected_token",
]


@dataclass(frozen=True, slots=True)
class AggregatorSemanticIssue:
    """A boundary of the verified subset, not necessarily engine rejection."""

    code: AggregatorIssueCode
    offset: int
    message: str


@dataclass(frozen=True, slots=True)
class AggregatorPair:
    """One ordered AttributePair emitted by the confirmed lowering path."""

    index: int
    left: str
    operator: Literal["&", "|"]
    right: str
    generated_name: str | None
    record_id_binding: Literal["intermediate(-1)", "original"]
    fuzzy_binding: Literal["false", "record_flag_bit_0"]


@dataclass(frozen=True, slots=True)
class AggregatorProgram:
    """Symbolic AttributePair program, not an engine-equivalent Boolean AST."""

    source: bytes
    normalized_expression: str
    pairs: tuple[AggregatorPair, ...]
    issue: AggregatorSemanticIssue | None = None

    @property
    def terminal_pair(self) -> AggregatorPair | None:
        return self.pairs[-1] if self.pairs else None

    @property
    def semantic_status(self) -> Literal["verified_subset", "unsupported", "ignored"]:
        if self.issue is None:
            return "verified_subset"
        return "ignored" if self.issue.code == "receiver_ignored" else "unsupported"


class _AggregatorParseError(Exception):
    def __init__(self, code: AggregatorIssueCode, offset: int, message: str):
        self.issue = AggregatorSemanticIssue(code, offset, message)


def _symbolic_name(index: int) -> bytes:
    """Represent an engine-generated name without claiming its global counter."""
    return f"#ATTR_{index:08x}".encode()


def _make_pair(
    pairs: list[AggregatorPair],
    left: bytes,
    operator: int,
    right: bytes,
    *,
    terminal: bool,
) -> bytes:
    for offset, operand in ((0, left), (1, right)):
        if len(operand) > 63:
            raise _AggregatorParseError(
                "operand_too_long",
                offset,
                f"lowered operand is {len(operand)} bytes; maximum is 63",
            )
    index = len(pairs)
    generated = None if terminal else _symbolic_name(index)
    pairs.append(
        AggregatorPair(
            index=index,
            left=left.decode("latin-1"),
            operator=chr(operator),
            right=right.decode("latin-1"),
            generated_name=None if generated is None else generated.decode(),
            record_id_binding="original" if terminal else "intermediate(-1)",
            fuzzy_binding="record_flag_bit_0" if terminal else "false",
        )
    )
    return b"" if generated is None else generated


def _lower_subexpression(
    source: bytes,
    pairs: list[AggregatorPair],
    *,
    terminal: bool,
) -> bytes:
    """Lower the statically confirmed ParseSubExpression subset to pairs."""
    if not source:
        raise _AggregatorParseError("empty_expression", 0, "expression is empty")

    operands: list[bytes] = []
    operators: list[int] = []
    start = 0
    for cursor, byte in enumerate(source):
        if byte in b"&|":
            operands.append(source[start:cursor])
            operators.append(byte)
            start = cursor + 1
        elif byte in b"()":
            raise _AggregatorParseError(
                "unbalanced_parentheses",
                cursor,
                "parenthesis remained after innermost lowering",
            )
    operands.append(source[start:])

    leading_operator = operators[0] if operands[0] == b"" and operators else None
    trailing_operator = operators[-1] if operands[-1] == b"" and operators else None
    if leading_operator is not None:
        operands = operands[1:]
        operators = operators[1:]
    if trailing_operator is not None:
        operands = operands[:-1]
        operators = operators[:-1]
    if not operands:
        raise _AggregatorParseError(
            "empty_operand", 0, "separator-only expression is unsupported"
        )
    if any(not operand for operand in operands):
        raise _AggregatorParseError(
            "empty_operand", 0, "multiple or internal empty operands are unsupported"
        )
    if any(len(operand) > 63 for operand in operands):
        offending = next(operand for operand in operands if len(operand) > 63)
        raise _AggregatorParseError(
            "operand_too_long",
            source.find(offending),
            f"operand is {len(offending)} bytes; maximum is 63",
        )

    # A single operand is encoded as a duplicate pair.  A single leading or
    # trailing separator selects its operator; an ordinary single operand uses
    # the engine's observed default '|'.
    if len(operands) == 1:
        operator = leading_operator or trailing_operator or ord("|")
        return _make_pair(pairs, operands[0], operator, operands[0], terminal=terminal)

    left = operands[0]
    for index, (operator, right) in enumerate(zip(operators, operands[1:])):
        is_last_normal_pair = index == len(operands) - 2
        pair_is_terminal = (
            terminal and is_last_normal_pair and trailing_operator is None
        )
        left = _make_pair(pairs, left, operator, right, terminal=pair_is_terminal)
    if trailing_operator is not None:
        left = _make_pair(pairs, left, trailing_operator, left, terminal=terminal)
    return left


def interpret_aggregator(parsed: AggregatorPayload) -> AggregatorProgram:
    """Lower the verified AddSignature subset into ordered AttributePair writes."""
    if parsed.decoded_sig_data is None:
        return AggregatorProgram(
            b"",
            "",
            (),
            AggregatorSemanticIssue(
                "receiver_ignored",
                0,
                "receiver ignored the record before expression parsing",
            ),
        )
    source = parsed.decoded_sig_data.split(b"\0", 1)[0]
    if b"#" in source:
        return AggregatorProgram(
            source,
            source.decode("latin-1"),
            (),
            AggregatorSemanticIssue(
                "source_marker", source.index(b"#"), "source marker '#' is unsupported"
            ),
        )
    if not source:
        return AggregatorProgram(
            source,
            "",
            (),
            AggregatorSemanticIssue("empty_expression", 0, "expression is empty"),
        )

    try:
        normalized = source
        pairs: list[AggregatorPair] = []
        while b")" in normalized:
            closing = normalized.index(b")")
            opening = normalized.rfind(b"(", 0, closing)
            if opening < 0:
                raise _AggregatorParseError(
                    "unbalanced_parentheses",
                    closing,
                    "closing parenthesis has no opening pair",
                )
            inner = normalized[opening + 1 : closing]
            if not inner:
                raise _AggregatorParseError(
                    "empty_operand", opening + 1, "empty parenthesized expression"
                )
            replacement = (
                _lower_subexpression(inner, pairs, terminal=False)
                if b"&" in inner or b"|" in inner
                else inner
            )
            suffix = normalized[closing + 1 :]
            if len(suffix) > 1023:
                raise _AggregatorParseError(
                    "unexpected_token",
                    closing + 1,
                    "parenthesis rewrite suffix exceeds 1023 bytes",
                )
            normalized = normalized[:opening] + replacement + suffix
        if b"(" in normalized:
            raise _AggregatorParseError(
                "unbalanced_parentheses",
                normalized.index(b"("),
                "opening parenthesis has no closing pair",
            )
        _lower_subexpression(normalized, pairs, terminal=True)
        return AggregatorProgram(
            source,
            normalized.decode("latin-1"),
            tuple(pairs),
        )
    except _AggregatorParseError as error:
        return AggregatorProgram(source, source.decode("latin-1"), (), error.issue)


def _projection_operand(value: str, expressions: dict[str, Expr]) -> Expr:
    """Build a readable projection without claiming runtime truth equivalence."""
    if value in expressions:
        return expressions[value]
    if value.startswith("!") and len(value) > 1:
        return Not(Atom(value[1:]))
    return Atom(value)


def _human_projection(program: AggregatorProgram) -> str | None:
    """Render the pair graph as Boolean-like text for humans only."""
    expressions: dict[str, Expr] = {}
    terminal: Expr | None = None
    for pair in program.pairs:
        left = _projection_operand(pair.left, expressions)
        right = _projection_operand(pair.right, expressions)
        expression: Expr = (
            And((left, right)) if pair.operator == "&" else Or((left, right))
        )
        if pair.generated_name is None:
            terminal = expression
        else:
            expressions[pair.generated_name] = expression
    return None if terminal is None else render_yara_like(terminal)


def _pair_json(pair: AggregatorPair) -> SemanticJSONValue:
    return JSONObject(
        (
            ("index", pair.index),
            ("left", pair.left),
            ("operator", pair.operator),
            ("right", pair.right),
            ("generated_name", pair.generated_name),
            ("record_id_binding", pair.record_id_binding),
            ("fuzzy_binding", pair.fuzzy_binding),
        )
    )


def _runtime_contract() -> JSONObject:
    """Pinned consumer facts, without executing or binding this local program."""
    return JSONObject(
        (
            ("scope", "positive attribute events in the pinned runtime consumer"),
            ("engine_equivalent_evaluator", False),
            (
                "event_lookup",
                "exact complete C string; no synthetic-ID or affix parsing",
            ),
            (
                "synthetic_prefix_effect",
                "#ATTR_ bypasses sigtree only; pair lookup remains exact",
            ),
            ("ir_pair_index_scope", "record-local zero-based symbolic index"),
            ("engine_pair_id_scope", "database-global one-based vector index"),
            ("local_to_engine_pair_id_binding", None),
            (
                "generated_names_scope",
                "local symbolic placeholders, not recovered engine names",
            ),
            (
                "state_lifecycle",
                "SCAN_REPLY/caller-owned runtime state; reset timing unknown",
            ),
            ("stateless_expression_evaluation", False),
            (
                "pair_state",
                JSONObject(
                    (
                        ("left_event_bit", 1),
                        ("right_event_bit", 2),
                        ("update", "state |= incoming"),
                        (
                            "duplicate_suppression",
                            "skip when existing state already contains incoming",
                        ),
                        ("or_operator_code", 0),
                        ("or_completion", "state != 0"),
                        ("and_operator_code", 1),
                        ("and_completion", "state == 3"),
                        ("completion_latch", 3),
                        (
                            "latch_order",
                            "before candidate policy; policy rejection does not roll it back",
                        ),
                    )
                ),
            ),
            (
                "intermediate_event",
                "recid -1 re-emits generated_name unchanged through MpAggregateAttributeExInternal",
            ),
            ("set_attribute_return", "candidate RecID or 0xFFFFFFFF"),
            ("set_attribute_out_flag", "candidate fuzzy state"),
            (
                "wrapper_result",
                JSONObject(
                    (
                        (
                            "0",
                            "no usable candidate, including delayed-detection filtering",
                        ),
                        ("1", "nonfuzzy candidate"),
                        ("2", "fuzzy candidate"),
                    )
                ),
            ),
            ("wrapper_result_is_verdict", False),
        )
    )


def export_aggregator_semantics(parsed: AggregatorPayload) -> RuleSemantics:
    program = interpret_aggregator(parsed)
    issue = program.issue
    projection = _human_projection(program)
    interpretation = (
        None
        if issue is not None
        else JSONObject(
            (
                ("kind", "attribute_pair_program"),
                ("source_c_string", program.source.decode("latin-1")),
                ("normalized_expression", program.normalized_expression),
                ("synthetic_names", "local symbolic names; engine counter is global"),
                ("pairs", JSONArray(tuple(_pair_json(pair) for pair in program.pairs))),
                (
                    "human_projection",
                    None
                    if projection is None
                    else JSONObject(
                        (
                            ("syntax", "yara-like boolean text"),
                            ("text", projection),
                            ("engine_equivalent", False),
                        )
                    ),
                ),
            )
        )
    )
    claims = (
        SemanticClaim(
            id="aggregator_wire_layout",
            scope="wire_layout",
            statement=(
                "The receiver envelope contains flags, name length, signature "
                "length, bounded name/signature spans, and bytes trailing the "
                "declared signature span."
            ),
            coverage="complete",
            evidence_refs=("aggregator_receivers",),
        ),
        SemanticClaim(
            id="aggregator_loader_dispatch",
            scope="loader_dispatch",
            statement=(
                "The aggregator module registers the 0x96/0xE7 receiver family "
                "during engine database initialization."
            ),
            coverage="subset",
            evidence_refs=("aggregator_dispatch",),
            unknowns=(
                SemanticUnknown(
                    "loader_dispatch",
                    "The complete module-table and version-dependent registration "
                    "lifecycle is outside this record IR.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_receiver_transform",
            scope="receiver_transform",
            statement=(
                "Unknown flag bits cause a receiver no-op; accepted 0x96 data is "
                "passed directly and 0xE7 data is substitution-decoded before "
                "AddSignature lowers the confirmed C-string subset into ordered "
                "AttributePair writes."
            ),
            coverage="subset",
            evidence_refs=("aggregator_receivers", "aggregator_pair_lowering"),
            unknowns=(
                SemanticUnknown(
                    "receiver_transform",
                    "Malformed and repeated-empty separator paths, exception "
                    "propagation, global synthetic-name counter state, and fuzzy "
                    "matching behavior are not fully modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_runtime_consumer",
            scope="runtime_consumer",
            statement=(
                "SetAttribute resolves complete C-string event names exactly, "
                "without parsing synthetic IDs or affixes; #ATTR_ only bypasses "
                "sigtree. Runtime pair IDs are database-global and one-based, "
                "not local IR indices plus one. Separate negative-attribute "
                "finalization looks up the corresponding positive name."
            ),
            coverage="subset",
            evidence_refs=(
                "aggregator_runtime_name_lookup",
                "aggregator_negated_attribute_consumer",
            ),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "Full negative-attribute finalization, database-global ID/name "
                    "bindings for this local IR, and caller-owned state reset "
                    "timing are not modeled.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_runtime_pair_state",
            scope="runtime_consumer",
            statement=(
                "Exact left/right events contribute bits 1/2, merged by OR; "
                "events already represented in state are suppressed. A completed "
                "pair is latched to state 3 before candidate policy, and policy "
                "rejection does not roll back that latch."
            ),
            coverage="subset",
            evidence_refs=("aggregator_pair_state_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "State allocation/reset across caller lifecycles and full "
                    "negative/fuzzy interactions are outside this positive-event contract.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_runtime_candidate_handoff",
            scope="runtime_consumer",
            statement=(
                "A recid=-1 pair re-emits its generated_name unchanged through "
                "MpAggregateAttributeExInternal. SetAttribute returns candidate "
                "RecID or 0xFFFFFFFF and outputs candidate fuzzy state. Wrapper "
                "results 0/1/2 mean no usable/nonfuzzy/fuzzy candidate, not verdict; "
                "MpAggregateAttributeEx can also return a filtered cached candidate."
            ),
            coverage="subset",
            evidence_refs=("aggregator_candidate_handoff_consumer",),
            unknowns=(
                SemanticUnknown(
                    "runtime_consumer",
                    "Complete candidate arbitration, fuzzy matching rules, policy "
                    "acceptance and report mapping are not evaluated.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_detection_predicate",
            scope="detection_predicate",
            statement=(
                "The local pair gate completes OR (op=0) when state!=0 and "
                "AND (op=1) when state==3. Original predicate instructions were "
                "tested for op 0/1/2 and state 0..3 only; this does not establish "
                "a complete engine-equivalent expression evaluator."
            ),
            coverage="subset",
            evidence_refs=(
                "aggregator_pair_gate_consumer",
                "aggregator_pair_gate_native",
            ),
            unknowns=(
                SemanticUnknown(
                    "detection_predicate",
                    "The bounded native test excludes lookup, state merge/latch, "
                    "intermediate recursion, full negative/fuzzy semantics, "
                    "arbitration and caller state lifecycle.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_report_mapping",
            scope="report_mapping",
            statement=(
                "A terminal AttributePair recid cannot yet be mapped directly to "
                "a reported threat result."
            ),
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "report_mapping",
                    "MpFinalizeAggregation provides a downstream handoff path, "
                    "not a complete report or policy mapping.",
                ),
            ),
        ),
        SemanticClaim(
            id="aggregator_final_verdict",
            scope="final_verdict",
            statement="An aggregator program is not a confirmed final verdict.",
            coverage="unknown",
            unknowns=(
                SemanticUnknown(
                    "final_verdict",
                    "Downstream policy, candidate arbitration, and final reporting "
                    "remain outside the record-level model.",
                ),
            ),
        ),
    )
    claim_evidence = (
        SemanticEvidence(
            id="aggregator_dispatch",
            axis="dispatch",
            kind="engine_static",
            source_ref="mpengine.dll 1.443.903.0 aggregator_init_module",
            locator="0x180488D60",
            supports=("aggregator_loader_dispatch",),
        ),
        SemanticEvidence(
            id="aggregator_receivers",
            axis="receiver",
            kind="engine_static",
            source_ref=(
                "mpengine.dll 1.443.903.0 aggregator_receiver / aggregatorex_receiver"
            ),
            locator="0x1804BEE00 / 0x1800FE270",
            supports=("aggregator_wire_layout", "aggregator_receiver_transform"),
        ),
        SemanticEvidence(
            id="aggregator_pair_lowering",
            axis="receiver",
            kind="engine_static",
            source_ref=(
                "mpengine.dll 1.443.903.0 AttributeAggregator::AddSignature / "
                "AttributeAggregator::ParseSubExpression"
            ),
            locator="0x1800FE5CC / 0x1800FB80C",
            supports=("aggregator_receiver_transform",),
        ),
        SemanticEvidence(
            id="aggregator_negated_attribute_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref=(
                "mpengine.dll 1.443.903.0 RuntimeAggregator::UpdateNegatedAttributes"
            ),
            locator="0x1800A76D0",
            supports=("aggregator_runtime_consumer",),
        ),
        SemanticEvidence(
            id="aggregator_runtime_name_lookup",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine.dll 1.443.903.0 RuntimeAggregator::SetAttribute",
            locator="0x1800A82B8-0x1800A838B / 0x1800A8409-0x1800A845E / 0x1800A8B1D-0x1800A8B34",
            supports=("aggregator_runtime_consumer",),
        ),
        SemanticEvidence(
            id="aggregator_pair_state_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref="mpengine.dll 1.443.903.0 RuntimeAggregator::SetAttribute",
            locator="0x1800A846E-0x1800A84D3 / 0x1800A935E-0x1800A9381 / 0x1800A8839",
            supports=("aggregator_runtime_pair_state",),
        ),
        SemanticEvidence(
            id="aggregator_candidate_handoff_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref=(
                "mpengine.dll 1.443.903.0 RuntimeAggregator::SetAttribute / "
                "MpAggregateAttributeExInternal / MpAggregateAttributeEx"
            ),
            locator="0x1800A8DA9-0x1800A8DBB / 0x1800A80B0 / 0x1800B2824",
            supports=("aggregator_runtime_candidate_handoff",),
        ),
        SemanticEvidence(
            id="aggregator_pair_gate_consumer",
            axis="consumer",
            kind="engine_static",
            source_ref=(
                "mpengine.dll 1.443.903.0 SetAttribute predicate; operator codes "
                "cross-checked against ParseSubExpression"
            ),
            locator="0x1800A87F7-0x1800A8816 / 0x1800A89AE / 0x1800FBBDA-0x1800FBBEF",
            supports=("aggregator_detection_predicate",),
        ),
        SemanticEvidence(
            id="aggregator_pair_gate_native",
            axis="engine_equivalent_test",
            kind="engine_equivalent_test",
            source_ref=(
                "original predicate slices only, pinned DLL SHA256 "
                "928e171c60a44bb326776d2a356412ae98d78469bdf8c94ebfbfa09f8ec4b4b3; "
                "12 bounded op/state cases, not full SetAttribute execution"
            ),
            locator="0x1800A87F7+0x25 / 0x1800A89AE+0x09; op=0,1,2 and state=0..3",
            supports=("aggregator_detection_predicate",),
        ),
    )
    return RuleSemantics(
        status=(
            "confirmed_subset"
            if issue is None
            else "ignored"
            if issue.code == "receiver_ignored"
            else "unsupported"
        ),
        representation="aggregator.attribute_pair_program.ir.v4",
        data=JSONObject(
            (
                (
                    "wire",
                    JSONObject(
                        (
                            ("family", _FAMILY_NAMES[parsed.type_byte]),
                            ("type_byte", parsed.type_byte),
                            ("raw_hex", parsed.raw.hex()),
                            ("flags", parsed.flags),
                            ("receiver_ignored", parsed.receiver_ignored),
                            ("name_length_declared", parsed.name_len),
                            ("name_raw_hex", parsed.name.hex()),
                            ("sig_length_declared", parsed.sig_len),
                            ("sig_data_raw_hex", parsed.sig_data.hex()),
                            (
                                "decoded_sig_data_hex",
                                None
                                if parsed.decoded_sig_data is None
                                else parsed.decoded_sig_data.hex(),
                            ),
                            ("trailing_raw_hex", parsed.trailing.hex()),
                            ("body_complete", parsed.body_complete),
                        )
                    ),
                ),
                ("interpretation", interpretation),
                ("runtime_contract", _runtime_contract()),
            )
        ),
        evidence=("mpengine 1.443.903.0 AddSignature expression subset",),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                issue.code,
                issue.message,
                (("offset", issue.offset),),
            ),
        )
        if issue is not None
        else (),
        claims=claims,
        claim_evidence=claim_evidence,
    )


def parse_aggregator(payload: bytes, *, type_byte: int) -> AggregatorPayload:
    """Parse either receiver envelope; ValueError denotes malformed input.

    For known flags only, a truncated name/signature is a receiver error
    (0x800C). Unknown flags are retained as an ignored record, matching the
    receiver's return 0 before checking those lengths. Downstream expression
    validation, name registration and RecID creation are outside this parser.
    """
    if type_byte not in _FAMILY_NAMES:
        raise ValueError(f"unsupported aggregator type {type_byte:#04x}")
    if len(payload) < 4:
        raise ValueError("truncated aggregator header: need 4 bytes")

    flags, name_len = payload[:2]
    sig_len = int.from_bytes(payload[2:4], "little")
    name_end = 4 + name_len
    sig_end = name_end + sig_len
    ignored = bool(flags & 0xFE)
    if not ignored:
        if name_end > len(payload):
            raise ValueError("truncated aggregator name")
        if sig_end > len(payload):
            raise ValueError("truncated aggregator sig_data")

    sig_data = payload[name_end:sig_end]
    decoded = None
    if not ignored:
        decoded = (
            sig_data.translate(PATTERN_DECODING_TABLE)
            if type_byte == AAGGREGATOREX_TYPE
            else sig_data
        )
    return AggregatorPayload(
        raw=payload,
        type_byte=type_byte,
        flags=flags,
        name_len=name_len,
        sig_len=sig_len,
        name=payload[4:name_end],
        sig_data=sig_data,
        trailing=payload[sig_end:],
        decoded_sig_data=decoded,
    )


def _preview(data: bytes) -> str:
    shown = data[:32].hex(" ")
    suffix = " ..." if len(data) > 32 else ""
    return f"{len(data)} B [{shown}{suffix}]"


def _text_preview(data: bytes) -> str:
    # Escape control characters, ANSI sequences and arbitrary bytes for loggers.
    shown = ascii(data[:160].decode("latin-1"))
    return shown + (" ..." if len(data) > 160 else "")


def render_aggregator(parsed: AggregatorPayload) -> FormatResult:
    """Render bounded sections; byte decoding does not imply a validated AST."""
    flags = f"{parsed.flags:#04x}"
    if parsed.unknown_flag_bits:
        flags += f", unknown={parsed.unknown_flag_bits:#04x}"
    sections = [
        DisplaySection(
            "Aggregator Envelope",
            rows=(
                ("family", _FAMILY_NAMES[parsed.type_byte]),
                ("flags", flags),
                (
                    "terminal_pair_metadata",
                    "fuzzy (matching effect unverified)" if parsed.fuzzy else "none",
                ),
                (
                    "receiver_status",
                    "ignored: unknown flag bits (return 0)"
                    if parsed.receiver_ignored
                    else "envelope accepted; downstream validation not evaluated",
                ),
                ("name_len", str(parsed.name_len)),
                ("sig_len", str(parsed.sig_len)),
                ("body_complete", str(parsed.body_complete).lower()),
                ("name_preview", _text_preview(parsed.name)),
                *(
                    (("sig_data_raw", _preview(parsed.sig_data)),)
                    if parsed.decoded_sig_data is None
                    else ()
                ),
                ("trailing_len", str(len(parsed.trailing))),
            ),
        ),
    ]
    if parsed.decoded_sig_data is None:
        sections.append(
            DisplaySection(
                "Aggregator Expression",
                rows=(("decode_status", "not evaluated: receiver ignores record"),),
            )
        )
    else:
        decoded = parsed.decoded_sig_data
        # AddSignature copies sig_len bytes, appends NUL, then uses C strings.
        # Preserve bytes following an embedded NUL separately from its text view.
        expression = decoded.split(b"\0", 1)[0]
        program = interpret_aggregator(parsed)
        projection = _human_projection(program)
        sections.append(
            DisplaySection(
                "Aggregator Expression",
                rows=(
                    (
                        "byte_decoding",
                        "pattern substitution table (mpengine 1.443.903.0)"
                        if parsed.type_byte == AAGGREGATOREX_TYPE
                        else "none: plain expression bytes",
                    ),
                    *(
                        (("expression_preview", _text_preview(expression)),)
                        if not expression or expression.decode("latin-1").isprintable()
                        else (("decoded_raw", _preview(decoded)),)
                    ),
                    (
                        "post_nul_length",
                        str(len(decoded) - len(expression) - (b"\0" in decoded)),
                    ),
                    ("semantic_status", program.semantic_status),
                    *(
                        (("pair_count", str(len(program.pairs))),)
                        if program.issue is None
                        else ()
                    ),
                    *(
                        (("normalized", program.normalized_expression),)
                        if program.issue is None
                        else ()
                    ),
                    *(
                        (
                            (
                                "human_projection",
                                f"{projection} (non-equivalent)",
                            ),
                        )
                        if projection is not None
                        else ()
                    ),
                    *(
                        (
                            (
                                "semantic_issue",
                                f"{program.issue.code} at byte {program.issue.offset}: {program.issue.message}",
                            ),
                        )
                        if program.issue is not None
                        else ()
                    ),
                ),
            )
        )
    return FormatResult(sections=tuple(sections))


AGGREGATOR_SPECS = (
    FamilySpec(
        AAGGREGATOR_TYPE,
        "AAGGREGATOR",
        partial(parse_aggregator, type_byte=AAGGREGATOR_TYPE),
        render_aggregator,
        semantic_exporter=export_aggregator_semantics,
    ),
    FamilySpec(
        AAGGREGATOREX_TYPE,
        "AAGGREGATOREX",
        partial(parse_aggregator, type_byte=AAGGREGATOREX_TYPE),
        render_aggregator,
        semantic_exporter=export_aggregator_semantics,
    ),
)
