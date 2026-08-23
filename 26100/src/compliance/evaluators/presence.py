"""Deterministic evaluator for document presence and existence requirements."""

from typing import Optional

try:
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.evidence.models import Evidence
    from src.requirements.models import Requirement
except ImportError:
    from compliance.models import ComplianceResult, ComplianceStatus
    from evidence.models import Evidence
    from requirements.models import Requirement


def evaluate_presence_requirement(
    req: Requirement,
    evidence: Evidence,
    bidder_id: Optional[str] = None,
) -> ComplianceResult:
    """Deterministically evaluate document or certificate presence requirements."""
    doc_name = req.parameter or req.required_value or req.original_text

    loc_parts = []
    if evidence.document_id:
        loc_parts.append(f"document '{evidence.document_id}'")
    if evidence.page is not None:
        loc_parts.append(f"page {evidence.page}")
    loc_str = f" in {', '.join(loc_parts)}" if loc_parts else ""

    # 1. Check for explicit contradiction (e.g. expired certificate, rejection notice)
    if evidence.is_contradictory:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NON_COMPLIANT,
            comparison="Certificate/Document INVALID/EXPIRED",
            explanation=(
                f"Required document '{doc_name}' is invalid or contradictory{loc_str}: "
                f"'{evidence.text}'."
            ),
            confidence=evidence.confidence or 1.0,
            evidence_ids=[evidence.evidence_id],
        )

    # 2. Check for ambiguity / unverified documents
    if evidence.is_ambiguous:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison="Document status AMBIGUOUS",
            explanation=(
                f"Evidence for required document '{doc_name}' is ambiguous or unverified{loc_str}: "
                f"'{evidence.text}'."
            ),
            confidence=evidence.confidence or 0.5,
            evidence_ids=[evidence.evidence_id],
        )

    # 3. Check for partial submission
    if evidence.is_partial:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            comparison="Document submission PARTIAL",
            explanation=(
                f"Required document '{doc_name}' is only partially fulfilled{loc_str}: "
                f"'{evidence.text}'."
            ),
            confidence=evidence.confidence or 0.8,
            evidence_ids=[evidence.evidence_id],
        )

    # 4. Valid document found
    return ComplianceResult(
        requirement_id=req.requirement_id,
        bidder_id=bidder_id,
        status=ComplianceStatus.COMPLIANT,
        comparison="Document PRESENT",
        explanation=f"Required document '{doc_name}' verified{loc_str}.",
        confidence=evidence.confidence if evidence.confidence is not None else 1.0,
        evidence_ids=[evidence.evidence_id],
    )
