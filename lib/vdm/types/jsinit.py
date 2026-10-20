"""Receiver-faithful byte-string model for JSINIT (0xCA)."""

import hashlib
import json
from dataclasses import dataclass
from typing import Final

from ..core import Artifact, ArtifactExport, DisplaySection, FamilySpec, FormatResult

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
    """Export the exact receiver input as a directly usable JavaScript artifact."""
    return ArtifactExport(
        "ready",
        artifacts=(Artifact("init.js", "javascript_source", parsed.raw),),
    )


SPEC = FamilySpec(
    JSINIT_TYPE,
    "JSINIT",
    parse_jsinit,
    render_jsinit,
    exporter=export_jsinit,
)
