"""Small constructors for evidence-backed, explicitly bounded type claims."""

from ..core import (
    EvidenceAxis,
    SemanticClaim,
    SemanticEvidence,
    SemanticScope,
    SemanticUnknown,
)


def scoped_claim(
    family: str,
    claim_name: str,
    scope: SemanticScope,
    statement: str,
    unknown_reason: str,
    axis: EvidenceAxis,
    locator: str,
) -> tuple[SemanticClaim, SemanticEvidence]:
    """Build one subset claim and its single typed source reference."""
    claim_id = f"{family}.{claim_name}"
    evidence_id = f"{claim_id}.static"
    return (
        SemanticClaim(
            id=claim_id,
            scope=scope,
            statement=statement,
            coverage="subset",
            evidence_refs=(evidence_id,),
            unknowns=(SemanticUnknown(scope, unknown_reason),),
        ),
        SemanticEvidence(
            id=evidence_id,
            axis=axis,
            kind="engine_static",
            source_ref="mpengine 1.443.903.0",
            locator=locator,
            supports=(claim_id,),
        ),
    )
