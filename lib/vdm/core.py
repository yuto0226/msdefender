import math
from collections.abc import Callable
from dataclasses import dataclass
from types import NoneType
from typing import TYPE_CHECKING, Literal, TypeVar

if TYPE_CHECKING:
    from .bm_yara import BmYaraRender

Field = tuple[str, str]


@dataclass(slots=True)
class DisplaySection:
    title: str
    rows: tuple[Field, ...] = ()
    bm_yara: "BmYaraRender | None" = None
    printable_preview: str | None = None
    yara_unsupported: tuple[str, ...] = ()


@dataclass(slots=True)
class FormatResult:
    fields: tuple[Field, ...] = ()
    sections: tuple[DisplaySection, ...] = ()


T = TypeVar("T")
Parser = Callable[[bytes], T]
Renderer = Callable[[T], FormatResult]

type JSONValue = NoneType | bool | int | float | str | tuple[JSONValue, ...]
type JSONDetails = tuple[tuple[str, JSONValue], ...]
type SemanticJSONValue = NoneType | bool | int | float | str | JSONArray | JSONObject
type SemanticJSONDetails = tuple[tuple[str, SemanticJSONValue], ...]


@dataclass(frozen=True, slots=True)
class JSONArray:
    """An immutable JSON array, including an unambiguous empty array."""

    items: tuple[SemanticJSONValue, ...]


@dataclass(frozen=True, slots=True)
class JSONObject:
    """An immutable JSON object represented by ordered key/value pairs."""

    items: tuple[tuple[str, SemanticJSONValue], ...]

    def __post_init__(self) -> None:
        if any(not isinstance(key, str) or not key for key, _ in self.items):
            raise ValueError("semantic JSON object keys must be non-empty strings")
        keys = tuple(key for key, _ in self.items)
        if len(keys) != len(set(keys)):
            raise ValueError("semantic JSON object keys must be unique")


SemanticStatus = Literal["confirmed_subset", "observed_only", "unsupported", "ignored"]
SemanticScope = Literal[
    "corpus_observation",
    "wire_layout",
    "loader_dispatch",
    "receiver_transform",
    "runtime_consumer",
    "detection_predicate",
    "report_mapping",
    "final_verdict",
]
SemanticCoverage = Literal["complete", "subset", "unknown"]
EvidenceAxis = Literal[
    "corpus",
    "wire_parser",
    "dispatch",
    "receiver",
    "consumer",
    "policy",
    "report",
    "engine_equivalent_test",
]
EvidenceKind = Literal[
    "engine_static",
    "engine_runtime",
    "corpus",
    "engine_equivalent_test",
]

_SCOPE_EVIDENCE_AXES: dict[SemanticScope, frozenset[EvidenceAxis]] = {
    "corpus_observation": frozenset({"corpus"}),
    "wire_layout": frozenset({"wire_parser", "receiver"}),
    "loader_dispatch": frozenset({"dispatch"}),
    "receiver_transform": frozenset({"receiver"}),
    "runtime_consumer": frozenset({"consumer", "engine_equivalent_test"}),
    "detection_predicate": frozenset({"consumer", "engine_equivalent_test"}),
    "report_mapping": frozenset({"policy", "report", "engine_equivalent_test"}),
    "final_verdict": frozenset({"report", "engine_equivalent_test"}),
}


@dataclass(frozen=True, slots=True)
class SemanticUnknown:
    """An explicit semantic gap attached to a scoped claim."""

    scope: SemanticScope
    reason: str

    def __post_init__(self) -> None:
        if self.scope not in _SCOPE_EVIDENCE_AXES:
            raise ValueError(f"invalid semantic unknown scope {self.scope!r}")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("semantic unknown reason must be a non-empty string")

    def to_json(self) -> dict[str, str]:
        return {"scope": self.scope, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class SemanticClaim:
    """One bounded semantic statement and its unresolved boundary."""

    id: str
    scope: SemanticScope
    statement: str
    coverage: SemanticCoverage
    evidence_refs: tuple[str, ...] = ()
    unknowns: tuple[SemanticUnknown, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("semantic claim id must be a non-empty string")
        if self.scope not in _SCOPE_EVIDENCE_AXES:
            raise ValueError(f"invalid semantic claim scope {self.scope!r}")
        if not isinstance(self.statement, str) or not self.statement:
            raise ValueError("semantic claim statement must be a non-empty string")
        if self.coverage not in {"complete", "subset", "unknown"}:
            raise ValueError(f"invalid semantic claim coverage {self.coverage!r}")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(ref, str) or not ref for ref in self.evidence_refs
        ):
            raise TypeError("semantic claim evidence refs must be non-empty strings")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("semantic claim evidence refs must be unique")
        if not isinstance(self.unknowns, tuple) or any(
            not isinstance(unknown, SemanticUnknown) for unknown in self.unknowns
        ):
            raise TypeError("semantic claim unknowns must be an immutable tuple")
        if self.coverage in {"complete", "subset"} and not self.evidence_refs:
            raise ValueError(
                f"{self.coverage} semantic claims require typed evidence refs"
            )
        if self.coverage in {"subset", "unknown"} and not self.unknowns:
            raise ValueError(
                f"{self.coverage} semantic claims require explicit unknowns"
            )
        if self.coverage == "complete" and any(
            unknown.scope == self.scope for unknown in self.unknowns
        ):
            raise ValueError(
                "complete semantic claims cannot retain unknowns in the same scope"
            )

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "scope": self.scope,
            "statement": self.statement,
            "coverage": self.coverage,
            "evidence_refs": list(self.evidence_refs),
            "unknowns": [unknown.to_json() for unknown in self.unknowns],
        }


@dataclass(frozen=True, slots=True)
class SemanticEvidence:
    """Typed evidence that may support only the named scoped claims."""

    id: str
    axis: EvidenceAxis
    kind: EvidenceKind
    source_ref: str
    supports: tuple[str, ...]
    locator: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("semantic evidence id must be a non-empty string")
        if self.axis not in {
            "corpus",
            "wire_parser",
            "dispatch",
            "receiver",
            "consumer",
            "policy",
            "report",
            "engine_equivalent_test",
        }:
            raise ValueError(f"invalid semantic evidence axis {self.axis!r}")
        if self.kind not in {
            "engine_static",
            "engine_runtime",
            "corpus",
            "engine_equivalent_test",
        }:
            raise ValueError(f"invalid semantic evidence kind {self.kind!r}")
        if not isinstance(self.source_ref, str) or not self.source_ref:
            raise ValueError("semantic evidence source_ref must be a non-empty string")
        if self.locator is not None and (
            not isinstance(self.locator, str) or not self.locator
        ):
            raise ValueError("semantic evidence locator must be a non-empty string")
        if (
            not isinstance(self.supports, tuple)
            or not self.supports
            or any(
                not isinstance(claim_id, str) or not claim_id
                for claim_id in self.supports
            )
        ):
            raise ValueError("semantic evidence supports must name at least one claim")
        if len(self.supports) != len(set(self.supports)):
            raise ValueError("semantic evidence supports must be unique")

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "axis": self.axis,
            "kind": self.kind,
            "source_ref": self.source_ref,
            "locator": self.locator,
            "supports": list(self.supports),
        }


@dataclass(frozen=True, slots=True)
class SemanticIssue:
    """Machine-readable reason a semantic export is incomplete or unavailable."""

    code: str
    message: str
    details: SemanticJSONDetails = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not isinstance(self.message, str):
            raise TypeError("semantic issue code and message must be strings")
        if not self.code or not self.message:
            raise ValueError("semantic issue code and message must be non-empty")
        if not isinstance(self.details, tuple):
            raise TypeError("semantic issue details must be an immutable tuple")
        keys: list[str] = []
        for entry in self.details:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("semantic issue details must contain key/value pairs")
            key, value = entry
            if not isinstance(key, str):
                raise TypeError("semantic issue detail keys must be strings")
            if not key:
                raise ValueError("semantic issue detail keys must be non-empty")
            keys.append(key)
            _validate_semantic_json_value(value)
        if len(keys) != len(set(keys)):
            raise ValueError("semantic issue detail keys must be unique")

    def to_json(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "details": {
                key: _to_semantic_json_value(value) for key, value in self.details
            },
        }


@dataclass(frozen=True, slots=True)
class RuleSemantics:
    """Immutable portable semantic envelope using immutable JSON-compatible data."""

    status: SemanticStatus
    representation: str
    data: SemanticJSONValue = None
    evidence: tuple[str, ...] = ()
    profile: str | None = None
    issues: tuple[SemanticIssue, ...] = ()
    claims: tuple[SemanticClaim, ...] = ()
    claim_evidence: tuple[SemanticEvidence, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {
            "confirmed_subset",
            "observed_only",
            "unsupported",
            "ignored",
        }:
            raise ValueError(f"invalid semantic status {self.status!r}")
        if not isinstance(self.representation, str):
            raise TypeError("semantic representation must be a string")
        if not self.representation:
            raise ValueError("semantic representation must be non-empty")
        _validate_semantic_json_value(self.data)
        if not isinstance(self.evidence, tuple) or any(
            not isinstance(item, str) for item in self.evidence
        ):
            raise TypeError("semantic evidence must be an immutable tuple of strings")
        if self.profile is not None and not isinstance(self.profile, str):
            raise TypeError("semantic profile must be a string or None")
        if self.status == "confirmed_subset":
            if not self.evidence or any(not item for item in self.evidence):
                raise ValueError(
                    "confirmed_subset semantics require non-empty engine evidence"
                )
            if not self.profile:
                raise ValueError(
                    "confirmed_subset semantics require a non-empty engine profile"
                )
        if not isinstance(self.issues, tuple) or any(
            not isinstance(issue, SemanticIssue) for issue in self.issues
        ):
            raise TypeError("semantic issues must be an immutable tuple")
        if not isinstance(self.claims, tuple) or any(
            not isinstance(claim, SemanticClaim) for claim in self.claims
        ):
            raise TypeError("semantic claims must be an immutable tuple")
        if not isinstance(self.claim_evidence, tuple) or any(
            not isinstance(item, SemanticEvidence) for item in self.claim_evidence
        ):
            raise TypeError("semantic claim evidence must be an immutable tuple")
        claim_ids = tuple(claim.id for claim in self.claims)
        evidence_ids = tuple(item.id for item in self.claim_evidence)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("semantic claim ids must be unique")
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("semantic evidence ids must be unique")
        claims_by_id = {claim.id: claim for claim in self.claims}
        evidence_by_id = {item.id: item for item in self.claim_evidence}
        for item in self.claim_evidence:
            missing = set(item.supports) - claims_by_id.keys()
            if missing:
                raise ValueError(
                    f"semantic evidence {item.id!r} supports unknown claims: "
                    f"{sorted(missing)!r}"
                )
        for claim in self.claims:
            missing = set(claim.evidence_refs) - evidence_by_id.keys()
            if missing:
                raise ValueError(
                    f"semantic claim {claim.id!r} references unknown evidence: "
                    f"{sorted(missing)!r}"
                )
            referenced = tuple(evidence_by_id[ref] for ref in claim.evidence_refs)
            if any(claim.id not in item.supports for item in referenced):
                raise ValueError(
                    f"semantic claim {claim.id!r} references evidence that does not "
                    "declare support for it"
                )
            if claim.coverage in {"complete", "subset"} and not any(
                item.axis in _SCOPE_EVIDENCE_AXES[claim.scope] for item in referenced
            ):
                allowed = sorted(_SCOPE_EVIDENCE_AXES[claim.scope])
                raise ValueError(
                    f"semantic claim {claim.id!r} scope {claim.scope!r} requires "
                    f"evidence on one of these axes: {allowed!r}"
                )

    def to_json(self) -> dict[str, object]:
        """Return standard-library-json-serializable envelope data."""
        return {
            "status": self.status,
            "representation": self.representation,
            "data": _to_semantic_json_value(self.data),
            "evidence": list(self.evidence),
            "profile": self.profile,
            "issues": [issue.to_json() for issue in self.issues],
            "claims": [claim.to_json() for claim in self.claims],
            "claim_evidence": [item.to_json() for item in self.claim_evidence],
        }


def _validate_semantic_json_value(value: SemanticJSONValue) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("semantic JSON numbers must be finite")
        return
    if isinstance(value, JSONArray):
        for item in value.items:
            _validate_semantic_json_value(item)
        return
    if isinstance(value, JSONObject):
        for key, item in value.items:
            if not key:
                raise ValueError("semantic JSON object keys must be non-empty")
            _validate_semantic_json_value(item)
        return
    raise TypeError(
        f"semantic value is not immutable JSON data: {type(value).__name__}"
    )


def _to_semantic_json_value(value: SemanticJSONValue) -> object:
    if isinstance(value, JSONArray):
        return [_to_semantic_json_value(item) for item in value.items]
    if isinstance(value, JSONObject):
        return {key: _to_semantic_json_value(item) for key, item in value.items}
    return value


def semantic_json_to_data(value: SemanticJSONValue) -> object:
    """Convert validated immutable semantic JSON data to plain JSON data."""
    _validate_semantic_json_value(value)
    return _to_semantic_json_value(value)


def _validate_json_value(value: JSONValue) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("artifact warning values must be finite JSON numbers")
        return
    if isinstance(value, tuple):
        for item in value:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                if not item[0]:
                    raise ValueError("artifact warning object keys must be non-empty")
                _validate_json_value(item[1])
            else:
                _validate_json_value(item)
        object_items = [
            item
            for item in value
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
        ]
        if object_items and len(object_items) == len(value):
            keys = [item[0] for item in object_items]
            if len(keys) != len(set(keys)):
                raise ValueError("artifact warning object keys must be unique")
        return
    raise TypeError(
        f"artifact warning value is not immutable JSON data: {type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    kind: str
    data: bytes

    def __post_init__(self) -> None:
        stem = self.name.split(".", 1)[0].rstrip(" ").casefold()
        reserved_stems = {"con", "prn", "aux", "nul", "conin$", "conout$"}
        numbered_device = (
            len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789¹²³"
        )
        if (
            not self.name
            or self.name in {".", ".."}
            or self.name.endswith((".", " "))
            or stem in reserved_stems
            or numbered_device
            or any(char in self.name for char in '/\\<>:"|?*')
            or any(ord(char) < 32 for char in self.name)
        ):
            raise ValueError("artifact name must be a safe local filename")


@dataclass(frozen=True, slots=True)
class ArtifactWarning:
    code: str
    message: str
    details: JSONDetails = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not isinstance(self.message, str):
            raise TypeError("artifact warning code and message must be strings")
        if not self.code or not self.message:
            raise ValueError("artifact warning code and message must be non-empty")
        if not isinstance(self.details, tuple):
            raise TypeError("artifact warning details must be an immutable tuple")
        keys: list[str] = []
        for entry in self.details:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise TypeError("artifact warning details must contain key/value pairs")
            key, value = entry
            if not isinstance(key, str):
                raise TypeError("artifact warning detail keys must be strings")
            if not key:
                raise ValueError(
                    "artifact warning detail keys must be non-empty strings"
                )
            keys.append(key)
            _validate_json_value(value)
        if len(keys) != len(set(keys)):
            raise ValueError("artifact warning detail keys must be unique")


@dataclass(frozen=True, slots=True)
class ArtifactExport:
    status: Literal["ready", "unsupported"]
    artifacts: tuple[Artifact, ...] = ()
    warnings: tuple[ArtifactWarning, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        names = [artifact.name.casefold() for artifact in self.artifacts]
        if len(names) != len(set(names)):
            raise ValueError("artifact names must be unique")
        if self.status == "unsupported" and self.artifacts:
            raise ValueError("unsupported artifact export cannot contain artifacts")
        if self.status == "ready" and not self.artifacts:
            raise ValueError("ready artifact export must contain artifacts")


SemanticExporter = Callable[[T], RuleSemantics]


@dataclass(frozen=True, slots=True)
class FamilySpec[T]:
    type_byte: int
    name: str
    parser: Parser[T]
    renderer: Renderer[T]
    exporter: Callable[[T], ArtifactExport] | None = None
    semantic_exporter: SemanticExporter[T] | None = None
