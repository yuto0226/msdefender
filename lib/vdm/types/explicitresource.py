"""Lossless parser and bounded renderer for EXPLICITRESOURCE (0xD6)."""

from dataclasses import dataclass
from typing import Final

from ..core import (
    DisplaySection,
    FamilySpec,
    FormatResult,
    JSONArray,
    JSONObject,
    RuleSemantics,
    SemanticIssue,
)

EXPLICITRESOURCE_TYPE: Final = 0xD6
_PATH_PREVIEW_CHARS: Final = 64
_TAIL_PREVIEW_BYTES: Final = 16


@dataclass(frozen=True, slots=True)
class ExplicitResourcePayload:
    """Parsed path and opaque optional tail, retaining the complete payload."""

    raw: bytes
    path_len: int
    path_raw: bytes
    tail_raw: bytes

    @property
    def path(self) -> str:
        """Decode the UTF-16LE path without losing isolated surrogate code units."""
        return self.path_raw.decode("utf-16le", errors="surrogatepass")


def parse_explicitresource(payload: bytes) -> ExplicitResourcePayload:
    """Parse the length-prefixed UTF-16LE path and preserve an optional tail."""
    if len(payload) < 2:
        raise ValueError(
            f"truncated EXPLICITRESOURCE path_len: need 2 bytes, have {len(payload)}"
        )

    path_len = int.from_bytes(payload[:2], "little")
    if path_len < 2:
        raise ValueError(
            f"invalid EXPLICITRESOURCE path_len: need at least 2 bytes, have {path_len}"
        )
    if path_len & 1:
        raise ValueError(
            f"invalid EXPLICITRESOURCE path_len: must be even, have {path_len}"
        )

    path_end = 2 + path_len
    if path_end > len(payload):
        raise ValueError(
            "truncated EXPLICITRESOURCE path: "
            f"need {path_len} bytes, have {len(payload) - 2}"
        )

    return ExplicitResourcePayload(
        raw=payload,
        path_len=path_len,
        path_raw=payload[2:path_end],
        tail_raw=payload[path_end:],
    )


def _hex_preview(data: bytes, limit: int) -> str:
    preview = data[:limit].hex(" ").upper()
    if len(data) > limit:
        preview += f" … ({len(data) - limit} more bytes)"
    return preview or "(empty)"


def render_explicitresource(parsed: ExplicitResourcePayload) -> FormatResult:
    """Render path and tail metadata with fixed-size previews."""
    path = parsed.path
    path_preview = ascii(path[:_PATH_PREVIEW_CHARS])
    if len(path) > _PATH_PREVIEW_CHARS:
        path_preview += f" … ({len(path) - _PATH_PREVIEW_CHARS} more chars)"

    return FormatResult(
        fields=(
            ("path_len", f"{parsed.path_len} B"),
            ("path_chars", str(len(path))),
            ("tail_len", f"{len(parsed.tail_raw)} B"),
            ("payload_len", f"{len(parsed.raw)} B"),
        ),
        sections=(
            DisplaySection(
                "Explicit Resource",
                rows=(
                    ("path", path_preview),
                    ("path_raw_preview", _hex_preview(parsed.path_raw, 24)),
                    (
                        "tail_raw_preview",
                        _hex_preview(parsed.tail_raw, _TAIL_PREVIEW_BYTES),
                    ),
                ),
            ),
        ),
    )


def export_explicitresource_semantics(
    parsed: ExplicitResourcePayload,
) -> RuleSemantics:
    """Export the confirmed path storage and case-insensitive runtime lookup."""
    try:
        path_text = parsed.path_raw.decode("utf-16le")
    except UnicodeDecodeError:
        path_text = None

    issues = [
        SemanticIssue(
            "recid_semantics_unknown",
            "The stored RecID is produced by createrecidp; its full meaning is "
            "not exported.",
        ),
        SemanticIssue(
            "final_verdict_unknown",
            "A matched explicit-resource row does not establish the final "
            "threat verdict.",
        ),
    ]
    if parsed.tail_raw:
        issues.append(
            SemanticIssue(
                "tail_grammar_unknown",
                "The receiver passes bytes after the bounded path to createrecidp "
                "without a confirmed tail grammar.",
                (("length", len(parsed.tail_raw)),),
            )
        )
    if path_text is None:
        issues.append(
            SemanticIssue(
                "invalid_utf16le_path",
                "The bounded path bytes are not valid UTF-16LE; no path lookup "
                "value is inferred.",
            )
        )
    elif "\0" in path_text:
        issues.append(
            SemanticIssue(
                "embedded_nul_path",
                "The receiver compares NUL-terminated paths; this payload "
                "contains an embedded NUL.",
            )
        )

    supported = path_text is not None and "\0" not in path_text and not parsed.tail_raw
    return RuleSemantics(
        status="confirmed_subset" if supported else "unsupported",
        representation="explicitresource.path_lookup.ir.v1",
        data=JSONObject(
            (
                ("raw_hex", parsed.raw.hex()),
                (
                    "framing",
                    JSONArray(
                        (
                            JSONObject(
                                (
                                    ("kind", "path_len"),
                                    ("offset", 0),
                                    ("length", 2),
                                    ("raw_hex", parsed.raw[:2].hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "path_utf16le"),
                                    ("offset", 2),
                                    ("length", parsed.path_len),
                                    ("raw_hex", parsed.path_raw.hex()),
                                )
                            ),
                            JSONObject(
                                (
                                    ("kind", "opaque_tail"),
                                    ("offset", 2 + parsed.path_len),
                                    ("length", len(parsed.tail_raw)),
                                    ("raw_hex", parsed.tail_raw.hex()),
                                )
                            ),
                        )
                    ),
                ),
                (
                    "path",
                    JSONObject(
                        (
                            ("encoding", "utf-16le"),
                            ("text", path_text),
                            ("raw_hex", parsed.path_raw.hex()),
                        )
                    ),
                ),
                (
                    "storage",
                    JSONObject(
                        (
                            ("kind", "explicitresource_row"),
                            ("row_size", 16),
                            ("path_storage", "kstore"),
                            ("recid_source", "createrecidp"),
                            ("recid_semantics", "unknown"),
                        )
                    ),
                ),
                (
                    "opaque_tail",
                    JSONObject(
                        (
                            ("raw_hex", parsed.tail_raw.hex()),
                            ("length", len(parsed.tail_raw)),
                        )
                    ),
                ),
                (
                    "lookup",
                    JSONObject(
                        (
                            ("kind", "path"),
                            (
                                "comparison",
                                "case_insensitive" if supported else "unknown",
                            ),
                            (
                                "result_role",
                                "matched_storage_row" if supported else "unknown",
                            ),
                        )
                    ),
                ),
                ("final_verdict", "unknown"),
            )
        ),
        evidence=(
            (
                "explicitresource_record::Load bounds the UTF-16LE path and stores "
                "it with a RecID"
            ),
            (
                "MpSignatureSubType<explicitresource_record>::Lookup uses _wcsicmp "
                "on stored and provider paths"
            ),
            "mpas.sig/mpav.sig corpus sample recorded in the 0xD6 format analysis",
        ),
        profile="mpengine-1.443.903.0",
        issues=tuple(issues),
    )


SPEC = FamilySpec(
    EXPLICITRESOURCE_TYPE,
    "EXPLICITRESOURCE",
    parse_explicitresource,
    render_explicitresource,
    semantic_exporter=export_explicitresource_semantics,
)

__all__ = [
    "EXPLICITRESOURCE_TYPE",
    "SPEC",
    "ExplicitResourcePayload",
    "export_explicitresource_semantics",
    "parse_explicitresource",
    "render_explicitresource",
]
