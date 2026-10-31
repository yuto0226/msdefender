"""Reproducible evidence inventory for VDM semantic exporters."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .record import decode_record
from .registry import DEFAULT_REGISTRY
from .semantic import export_record_semantics
from .stream import iter_wire_records

_FAILURE_PREVIEW_LIMIT = 100


def _source_identity(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    with resolved.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "path": str(resolved),
        "size": resolved.stat().st_size,
        "sha256": digest,
    }


def _sample_key(payload: bytes) -> tuple[int, bytes]:
    """Select deterministic shape variants without assigning wire semantics."""
    return len(payload), payload[:8]


def _record_failure(
    failures: list[dict[str, object]],
    *,
    source: str,
    offset: int,
    stage: str,
    error: str,
) -> None:
    if len(failures) < _FAILURE_PREVIEW_LIMIT:
        failures.append(
            {
                "source": source,
                "offset": offset,
                "stage": stage,
                "error": error,
            }
        )


@dataclass(slots=True)
class _SemanticAccumulator:
    sample_count: int = 0
    failure_count: int = 0
    statuses: Counter[str] = field(default_factory=Counter)
    representations: Counter[str] = field(default_factory=Counter)
    issues: Counter[str] = field(default_factory=Counter)
    profiles: Counter[str] = field(default_factory=Counter)
    evidence: set[str] = field(default_factory=set)
    claim_coverage: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    claim_unknowns: Counter[str] = field(default_factory=Counter)
    claim_unknown_reasons: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    claim_unknown_reason_records: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    claim_evidence_axes: dict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    failures: list[dict[str, object]] = field(default_factory=list)

    def observe(
        self,
        type_byte: int,
        payload: bytes,
        *,
        source: str,
        offset: int,
    ) -> None:
        self.sample_count += 1
        decoded = decode_record(type_byte, payload)
        if decoded.error is not None:
            self._fail(source, offset, "parse", decoded.error)
            return

        exported = export_record_semantics(decoded)
        if exported is None:
            self._fail(
                source,
                offset,
                "semantic",
                "semantic exporter is not registered",
            )
            return
        if exported.status == "failed":
            self._fail(
                source,
                offset,
                "semantic",
                exported.error or "unknown semantic export failure",
            )
            return

        assert exported.semantics is not None
        semantics = exported.semantics
        seen_unknown_reasons: set[tuple[str, str]] = set()
        self.statuses[semantics.status] += 1
        self.representations[semantics.representation] += 1
        self.issues.update(issue.code for issue in semantics.issues)
        self.profiles[semantics.profile or "unprofiled"] += 1
        self.evidence.update(semantics.evidence)
        evidence_by_id = {item.id: item for item in semantics.claim_evidence}
        for claim in semantics.claims:
            self.claim_coverage[claim.scope][claim.coverage] += 1
            for unknown in claim.unknowns:
                self.claim_unknowns[unknown.scope] += 1
                self.claim_unknown_reasons[unknown.scope][unknown.reason] += 1
                reason_key = (unknown.scope, unknown.reason)
                if reason_key not in seen_unknown_reasons:
                    self.claim_unknown_reason_records[unknown.scope][
                        unknown.reason
                    ] += 1
                    seen_unknown_reasons.add(reason_key)
            for evidence_ref in claim.evidence_refs:
                self.claim_evidence_axes[claim.scope][
                    evidence_by_id[evidence_ref].axis
                ] += 1

    def _fail(self, source: str, offset: int, stage: str, error: str) -> None:
        self.failure_count += 1
        _record_failure(
            self.failures,
            source=source,
            offset=offset,
            stage=stage,
            error=error,
        )


def build_semantic_inventory(
    paths: Iterable[Path],
    *,
    sample_limit_per_type: int = 64,
) -> dict[str, object]:
    """Inventory corpus framing and sampled semantic exports without overclaiming.

    Every record contributes to the framing/count tier. Semantic export is either
    performed for every record (``sample_limit_per_type == 0``) or for a
    deterministic set of distinct ``(payload length, first eight bytes)`` shapes.
    The latter is explicitly reported as sampled evidence and must not be treated
    as exhaustive branch coverage.
    """
    if sample_limit_per_type < 0:
        raise ValueError("sample_limit_per_type must be non-negative")

    sources = tuple(Path(path).resolve(strict=True) for path in paths)
    if not sources:
        raise ValueError("at least one .sig path is required")
    source_identities = [_source_identity(path) for path in sources]

    counts: Counter[int] = Counter()
    samples: dict[int, list[tuple[str, int, bytes]]] = defaultdict(list)
    sample_keys: dict[int, set[tuple[int, bytes]]] = defaultdict(set)
    semantics: dict[int, _SemanticAccumulator] = defaultdict(_SemanticAccumulator)

    for path in sources:
        for record in iter_wire_records(path):
            counts[record.type_byte] += 1
            key = _sample_key(record.payload)
            if sample_limit_per_type == 0:
                semantics[record.type_byte].observe(
                    record.type_byte,
                    record.payload,
                    source=str(path),
                    offset=record.offset,
                )
            elif (
                len(samples[record.type_byte]) < sample_limit_per_type
                and key not in sample_keys[record.type_byte]
            ):
                sample_keys[record.type_byte].add(key)
                samples[record.type_byte].append(
                    (str(path), record.offset, record.payload)
                )

    if sample_limit_per_type != 0:
        for type_byte, records in samples.items():
            for source, offset, payload in records:
                semantics[type_byte].observe(
                    type_byte,
                    payload,
                    source=source,
                    offset=offset,
                )

    final_source_identities = [_source_identity(path) for path in sources]
    if final_source_identities != source_identities:
        raise OSError("a source file changed while the inventory was being built")

    type_results: dict[str, object] = {}
    total_failure_count = 0
    types_with_scoped_claims: list[str] = []
    types_without_scoped_claims: list[str] = []
    types_with_evidence_backed_claims: list[str] = []
    types_without_evidence_backed_claims: list[str] = []
    types_with_only_unknown_claims: list[str] = []
    for type_byte in sorted(counts):
        spec = DEFAULT_REGISTRY.get(type_byte)
        accumulated = semantics[type_byte]
        total_failure_count += accumulated.failure_count
        declared_claim_scopes = set(accumulated.claim_coverage)
        semantic_scopes = sorted(
            set(accumulated.claim_coverage)
            | set(accumulated.claim_unknowns)
            | set(accumulated.claim_unknown_reasons)
            | set(accumulated.claim_evidence_axes)
        )
        type_key = f"0x{type_byte:02X}"
        if declared_claim_scopes:
            types_with_scoped_claims.append(type_key)
        else:
            types_without_scoped_claims.append(type_key)
        has_evidence_backed_claim = any(
            coverage in {"complete", "subset"} and count > 0
            for scope in declared_claim_scopes
            for coverage, count in accumulated.claim_coverage[scope].items()
        )
        if has_evidence_backed_claim:
            types_with_evidence_backed_claims.append(type_key)
        else:
            types_without_evidence_backed_claims.append(type_key)
            if declared_claim_scopes:
                types_with_only_unknown_claims.append(type_key)
        type_results[type_key] = {
            "name": spec.name if spec is not None else None,
            "record_count": counts[type_byte],
            "wire_evidence": {
                "tier": "corpus_observed",
                "framing": "all record boundaries reached by iter_wire_records",
            },
            "semantic_evidence": {
                "scope": "all_records"
                if sample_limit_per_type == 0
                else "deterministic_shape_sample",
                "sample_count": accumulated.sample_count,
                "unknown_reason_record_count_basis": (
                    "all_records"
                    if sample_limit_per_type == 0
                    else "deterministic_shape_sample"
                ),
                "status_counts": dict(accumulated.statuses),
                "representation_counts": dict(accumulated.representations),
                "profile_counts": dict(accumulated.profiles),
                "engine_evidence": sorted(accumulated.evidence),
                "claim_scope_counts": {
                    scope: {
                        "coverage_counts": dict(accumulated.claim_coverage[scope]),
                        "unknown_count": accumulated.claim_unknowns[scope],
                        "unknown_reasons": [
                            {
                                "reason": reason,
                                "occurrence_count": occurrences,
                                "sampled_record_count": accumulated.claim_unknown_reason_records[
                                    scope
                                ][reason],
                            }
                            for reason, occurrences in sorted(
                                accumulated.claim_unknown_reasons[scope].items()
                            )
                        ],
                        "evidence_axis_counts": dict(
                            accumulated.claim_evidence_axes[scope]
                        ),
                    }
                    for scope in semantic_scopes
                },
                "issue_counts": dict(accumulated.issues),
                "failure_count": accumulated.failure_count,
                "failure_preview": accumulated.failures,
                "failure_preview_truncated": accumulated.failure_count
                > len(accumulated.failures),
            },
        }

    registered_unobserved = [
        {
            "type": f"0x{type_byte:02X}",
            "name": spec.name,
        }
        for type_byte, spec in sorted(DEFAULT_REGISTRY.items())
        if type_byte not in counts
    ]
    return {
        "schema": "vdm-semantic-evidence-inventory.v5",
        "sources": source_identities,
        "sampling": {
            "scope": "all_records"
            if sample_limit_per_type == 0
            else "deterministic_shape_sample",
            "sample_limit_per_type": sample_limit_per_type,
            "shape_key": "payload_length + first_8_bytes",
            "exhaustive_record_export": sample_limit_per_type == 0,
            "exhaustive_semantic_branch_coverage": False,
        },
        "summary": {
            "record_count": sum(counts.values()),
            "observed_type_count": len(counts),
            "registered_type_count": len(DEFAULT_REGISTRY),
            "registered_unobserved_type_count": len(registered_unobserved),
            "semantic_failure_count": total_failure_count,
            "sampled_type_count_with_scoped_claims": len(types_with_scoped_claims),
            "sampled_type_count_without_scoped_claims": len(
                types_without_scoped_claims
            ),
            "sampled_type_count_with_evidence_backed_claims": len(
                types_with_evidence_backed_claims
            ),
            "sampled_type_count_without_evidence_backed_claims": len(
                types_without_evidence_backed_claims
            ),
            "sampled_type_count_with_only_unknown_claims": len(
                types_with_only_unknown_claims
            ),
        },
        "registered_unobserved_types": registered_unobserved,
        "sampled_observed_types_without_scoped_claims": types_without_scoped_claims,
        "sampled_observed_types_without_evidence_backed_claims": (
            types_without_evidence_backed_claims
        ),
        "sampled_observed_types_with_only_unknown_claims": (
            types_with_only_unknown_claims
        ),
        "types": type_results,
    }


__all__ = ["build_semantic_inventory"]
