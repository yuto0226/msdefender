"""Pure coordination of decoded records and family artifact exporters."""

from dataclasses import dataclass
from typing import Literal

from .core import Artifact, ArtifactWarning
from .record import DecodedRecord


@dataclass(frozen=True, slots=True)
class ArtifactResult:
    status: Literal["ready", "unsupported", "failed"]
    artifacts: tuple[Artifact, ...] = ()
    warnings: tuple[ArtifactWarning, ...] = ()
    reason: str | None = None
    error: str | None = None


def export_record_artifacts(record: DecodedRecord) -> ArtifactResult | None:
    """Run a record's optional exporter; never writes to the filesystem."""
    if record.spec is None or record.spec.exporter is None:
        return None
    if record.error is not None:
        return ArtifactResult(status="failed", error=record.error)
    try:
        exported = record.spec.exporter(record.value)
    except (TypeError, ValueError) as exc:
        return ArtifactResult(status="failed", error=str(exc))
    return ArtifactResult(
        status=exported.status,
        artifacts=exported.artifacts,
        warnings=exported.warnings,
        reason=exported.reason,
    )


__all__ = ["ArtifactResult", "export_record_artifacts"]
