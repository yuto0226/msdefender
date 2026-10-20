"""Receiver-faithful byte-string model for JSINIT (0xCA)."""

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
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

JSINIT_TYPE: Final = 0xCA
MAX_RECEIVER_SIZE: Final = 0xFFFFFFFF
TEXT_PREVIEW_BYTES: Final = 512


@dataclass(frozen=True, slots=True)
class JsInitPayload:
    """Bytes copied verbatim by ``pushJsInit`` and an optional UTF-8 view."""

    raw: bytes
    text: str | None


def parse_jsinit(payload: bytes) -> JsInitPayload:
    """Model the receiver's byte copy without imposing a text grammar."""
    if len(payload) > MAX_RECEIVER_SIZE:
        raise ValueError("JSINIT payload exceeds receiver UINT32_MAX size")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return JsInitPayload(raw=payload, text=text)


def _text_preview(raw: bytes) -> str:
    prefix = raw[:TEXT_PREVIEW_BYTES]
    while prefix:
        try:
            text = prefix.decode("utf-8")
        except UnicodeDecodeError:
            prefix = prefix[:-1]
            continue
        suffix = f" … ({len(raw)} B total)" if len(prefix) < len(raw) else ""
        return json.dumps(text, ensure_ascii=True) + suffix
    return "(not UTF-8)"


def render_jsinit(parsed: JsInitPayload) -> FormatResult:
    """Render bounded text and identity metadata for the global init blob."""
    return FormatResult(
        sections=(
            DisplaySection(
                "JSINIT",
                rows=(
                    ("length", f"{len(parsed.raw)} B"),
                    ("sha256", hashlib.sha256(parsed.raw).hexdigest()),
                    ("utf8", "valid" if parsed.text is not None else "invalid"),
                    ("preview", _text_preview(parsed.raw)),
                    ("engine_storage", "verbatim bytes plus internal NUL terminator"),
                ),
            ),
        )
    )


def export_jsinit(parsed: JsInitPayload) -> ArtifactExport:
    """Export the exact receiver bytes without claiming syntax validity."""
    return ArtifactExport(
        "ready",
        artifacts=(Artifact("init.js", "javascript_source", parsed.raw),),
    )


def export_jsinit_semantics(parsed: JsInitPayload) -> RuleSemantics:
    """Separate confirmed receiver bytes from JavaScript and verdict claims."""
    return RuleSemantics(
        status="observed_only",
        representation="jsinit.receiver_and_runtime.v1",
        data=JSONObject(
            (
                ("record_type", JSINIT_TYPE),
                (
                    "receiver_framing",
                    JSONObject(
                        (
                            ("kind", "opaque_length_bounded_byte_string"),
                            ("payload_length", len(parsed.raw)),
                            ("payload_bytes_hex", parsed.raw.hex()),
                            ("receiver_internal_terminator", "NUL after copied bytes"),
                            ("appended_terminator_in_payload", False),
                        )
                    ),
                ),
                (
                    "javascript_artifact",
                    JSONObject(
                        (
                            ("classification", "candidate_emulation_input"),
                            ("bytes_hex", parsed.raw.hex()),
                            ("encoding", "unknown"),
                            ("syntax_validated", False),
                        )
                    ),
                ),
                (
                    "init_runtime_consumer",
                    JSONObject(
                        (
                            ("consumer", "nscript::runJSEmulation"),
                            ("runtime_use", "JS emulation input"),
                            ("payload_to_scan_target_mapping", "unknown"),
                            ("detection_verdict", "unknown"),
                        )
                    ),
                ),
            )
        ),
        evidence=(
            (
                "mpengine 1.443.903.0 pushJsInit copies payload bytes and appends "
                "an internal NUL terminator"
            ),
            (
                "mpengine 1.443.903.0 nscript::runJSEmulation reads strJSInit and "
                "nJSInitSize"
            ),
        ),
        profile="mpengine-1.443.903.0",
        issues=(
            SemanticIssue(
                "javascript_encoding_unknown",
                "The receiver copies bytes without validating or identifying "
                "their text encoding.",
            ),
            SemanticIssue(
                "javascript_grammar_unvalidated",
                "The record is an input to JavaScript emulation, but this export "
                "does not parse or validate JavaScript source grammar.",
            ),
            SemanticIssue(
                "scan_target_mapping_unknown",
                "The relationship between JSINIT bytes and the UFS scan target "
                "is not established.",
            ),
            SemanticIssue(
                "detection_verdict_unknown",
                "Runtime emulation evidence does not establish a detection "
                "verdict or report mapping.",
            ),
        ),
    )


SPEC = FamilySpec(
    JSINIT_TYPE,
    "JSINIT",
    parse_jsinit,
    render_jsinit,
    exporter=export_jsinit,
    semantic_exporter=export_jsinit_semantics,
)
