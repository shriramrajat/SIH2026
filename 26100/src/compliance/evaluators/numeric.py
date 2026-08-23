"""Deterministic evaluator for numeric requirements."""

from typing import Any, Optional, Tuple

try:
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.compliance.units import convert_values_to_common_unit
    from src.evidence.models import Evidence
    from src.requirements.models import Requirement
except ImportError:
    from compliance.models import ComplianceResult, ComplianceStatus
    from compliance.units import convert_values_to_common_unit
    from evidence.models import Evidence
    from requirements.models import Requirement


def _format_num(val: float) -> str:
    """Format float cleanly, stripping trailing .0 for integers."""
    if val.is_integer():
        return str(int(val))
    return f"{val:.2f}".rstrip("0").rstrip(".")


def _try_parse_number(val: Any) -> Optional[float]:
    """Attempt to parse float or int from a value."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        cleaned = val.strip().replace(",", "")
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def evaluate_numeric_requirement(
    req: Requirement,
    evidence: Evidence,
    bidder_id: Optional[str] = None,
) -> ComplianceResult:
    """Deterministically evaluate numeric constraint against supplied evidence."""
    param_name = req.parameter or "value"
    op_str = str(req.operator.value if hasattr(req.operator, "value") else req.operator).strip()

    # 1. Parse numeric values
    req_num = _try_parse_number(req.required_value)
    evi_num = _try_parse_number(evidence.extracted_value)

    if req_num is None:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=(
                f"Requirement '{req.requirement_id}' has non-numeric required value "
                f"'{req.required_value}' for operator '{op_str}'."
            ),
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
        )

    if evi_num is None:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=(
                f"Bidder evidence does not contain a parseable numeric value "
                f"(extracted value: '{evidence.extracted_value}')."
            ),
            confidence=evidence.confidence or 0.8,
            evidence_ids=[evidence.evidence_id],
        )

    # 2. Normalize units
    converted = convert_values_to_common_unit(
        req_num, req.unit, evi_num, evidence.unit
    )
    if converted is None:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=(
                f"Incompatible or ambiguous units: requirement specifies '{req.unit}' "
                f"while evidence reports '{evidence.unit}'."
            ),
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
        )

    norm_req, norm_evi, unit_str = converted
    unit_suffix = f" {unit_str}" if unit_str else ""

    # 3. Perform comparison
    is_compliant = False
    if op_str == ">=":
        is_compliant = norm_evi >= norm_req
    elif op_str == "<=":
        is_compliant = norm_evi <= norm_req
    elif op_str == ">":
        is_compliant = norm_evi > norm_req
    elif op_str == "<":
        is_compliant = norm_evi < norm_req
    elif op_str in ("=", "==", "EQUALS", "EXACT"):
        is_compliant = abs(norm_evi - norm_req) < 1e-9
    elif op_str in ("!=", "NEQ"):
        is_compliant = abs(norm_evi - norm_req) >= 1e-9
    else:
        return ComplianceResult(
            requirement_id=req.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=f"Unsupported operator '{op_str}' for numeric evaluation.",
            confidence=1.0,
            evidence_ids=[evidence.evidence_id],
        )

    status = ComplianceStatus.COMPLIANT if is_compliant else ComplianceStatus.NON_COMPLIANT
    comp_expr = f"{_format_num(norm_evi)}{unit_suffix} {op_str} {_format_num(norm_req)}{unit_suffix}"

    # Build provenance-aware explanation
    evidence_desc = f"{_format_num(norm_evi)}{unit_suffix}"
    if evidence.unit and evidence.unit != unit_str:
        evidence_desc += f" (reported as {_format_num(evi_num)} {evidence.unit})"

    loc_parts = []
    if evidence.document_id:
        loc_parts.append(f"document '{evidence.document_id}'")
    if evidence.page is not None:
        loc_parts.append(f"page {evidence.page}")
    loc_str = f" in {', '.join(loc_parts)}" if loc_parts else ""

    explanation = (
        f"Required {param_name} {op_str} {_format_num(norm_req)}{unit_suffix}; "
        f"bidder evidence reports {evidence_desc}{loc_str}."
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
