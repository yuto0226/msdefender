"""Pure coordination of decoded records and family semantic exporters."""

from dataclasses import dataclass
from typing import Literal

from .core import RuleSemantics
from .record import DecodedRecord


@dataclass(frozen=True, slots=True)
class SemanticExportResult:
    """Execution outcome, separate from the evidence status in RuleSemantics."""

    status: Literal["ready", "failed"]
    semantics: RuleSemantics | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status == "ready":
            if self.semantics is None or self.error is not None:
                raise ValueError(
                    "ready semantic export requires semantics and no error"
                )
            return
        if self.status == "failed":
            if self.semantics is not None or not self.error:
                raise ValueError("failed semantic export requires only an error")
            return
        raise ValueError(f"invalid semantic export status {self.status!r}")


def export_record_semantics(record: DecodedRecord) -> SemanticExportResult | None:
    """Run a record's optional semantic exporter without writing to disk."""
    if record.spec is None or record.spec.semantic_exporter is None:
        return None
    if record.error is not None:
        return SemanticExportResult(status="failed", error=record.error)
    try:
        semantics = record.spec.semantic_exporter(record.value)
    except (TypeError, ValueError) as exc:
        return SemanticExportResult(status="failed", error=str(exc))
    return SemanticExportResult(status="ready", semantics=semantics)


__all__ = ["SemanticExportResult", "export_record_semantics"]
