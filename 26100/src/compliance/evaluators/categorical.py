"""Deterministic evaluator for categorical and text matching requirements."""

from typing import Any, Optional

try:
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.evidence.models import Evidence
    from src.requirements.models import Requirement
except ImportError:
    from compliance.models import ComplianceResult, ComplianceStatus
    from evidence.models import Evidence
    from requirements.models import Requirement


def _normalize_str(val: Any) -> str:
    """Normalize string for robust categorical comparison."""
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val).strip().lower()


def evaluate_categorical_requirement(
    req: Requirement,
    evidence: Evidence,
    bidder_id: Optional[str] = None,
) -> ComplianceResult:
    """Deterministically evaluate categorical equality or substring matching."""
    param_name = req.parameter or "specification"
    op_str = str(req.operator.value if hasattr(req.operator, "value") else req.operator).strip()

    req_norm = _normalize_str(req.required_value)
    evi_norm = _normalize_str(evidence.extracted_value if evidence.extracted_value is not None else evidence.text)

    if not req_norm:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=f"Requirement '{req.requirement_id}' lacks a defined target value.",
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
        )

    if not evi_norm:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=f"Bidder evidence does not contain a valid value to match against '{req.required_value}'.",
            confidence=evidence.confidence or 0.8,
            evidence_ids=[evidence.evidence_id],
        )

    # Check explicit flags on evidence
    if evidence.is_contradictory:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NON_COMPLIANT,
            comparison=f"'{evidence.extracted_value}' != '{req.required_value}'",
            explanation=f"Bidder evidence explicitly contradicts required {param_name} '{req.required_value}'.",
            confidence=evidence.confidence or 1.0,
            evidence_ids=[evidence.evidence_id],
        )

    if evidence.is_ambiguous:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=f"'{evidence.extracted_value}' ~ '{req.required_value}'",
            explanation=f"Bidder evidence for {param_name} is ambiguous or unverified.",
            confidence=evidence.confidence or 0.5,
            evidence_ids=[evidence.evidence_id],
        )

    if evidence.is_partial:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            comparison=f"'{evidence.extracted_value}' partially matches '{req.required_value}'",
            explanation=f"Bidder evidence only partially satisfies required {param_name} '{req.required_value}'.",
            confidence=evidence.confidence or 0.8,
            evidence_ids=[evidence.evidence_id],
        )

    # Operator evaluation
    is_compliant = False
    if op_str in ("=", "==", "EQUALS", "EXACT"):
        is_compliant = req_norm == evi_norm
    elif op_str == "CONTAINS":
        is_compliant = req_norm in evi_norm
    elif op_str in ("!=", "NEQ"):
        is_compliant = req_norm != evi_norm
    else:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=f"Unsupported operator '{op_str}' for categorical evaluation.",
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
        )

    status = ComplianceStatus.COMPLIANT if is_compliant else ComplianceStatus.NON_COMPLIANT
    comp_expr = f"'{evidence.extracted_value or evidence.text}' {op_str} '{req.required_value}'"

    loc_parts = []
    if evidence.document_id:
        loc_parts.append(f"document '{evidence.document_id}'")
    if evidence.page is not None:
        loc_parts.append(f"page {evidence.page}")
    loc_str = f" in {', '.join(loc_parts)}" if loc_parts else ""

    if is_compliant:
        explanation = (
            f"Required {param_name} '{req.required_value}'; "
            f"bidder evidence matches '{evidence.extracted_value or evidence.text}'{loc_str}."
        )
    else:
        explanation = (
            f"Required {param_name} '{req.required_value}'; "
            f"bidder evidence reports '{evidence.extracted_value or evidence.text}'{loc_str}."
        )

    return ComplianceResult(
        requirement_id=req.requirement_id,
        bidder_id=bidder_id,
        status=status,
        comparison=comp_expr,
        explanation=explanation,
        confidence=evidence.confidence if evidence.confidence is not None else 1.0,
        evidence_ids=[evidence.evidence_id],
    )
