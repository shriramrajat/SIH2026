"""Core deterministic compliance engine for PS 26100."""

from typing import Dict, List, Optional, Union

try:
    from src.compliance.evaluators.categorical import evaluate_categorical_requirement
    from src.compliance.evaluators.numeric import evaluate_numeric_requirement
    from src.compliance.evaluators.presence import evaluate_presence_requirement
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.evidence.models import Evidence
    from src.requirements.models import Operator, Requirement, RequirementCategory
except ImportError:
    from .evaluators.categorical import evaluate_categorical_requirement
    from .evaluators.numeric import evaluate_numeric_requirement
    from .evaluators.presence import evaluate_presence_requirement
    from .models import ComplianceResult, ComplianceStatus
    from evidence.models import Evidence
    from requirements.models import Operator, Requirement, RequirementCategory

_NUMERIC_OPERATORS = {
    Operator.GTE,
    Operator.LTE,
    Operator.GT,
    Operator.LT,
    Operator.EQ,
    Operator.EQUALS,
    Operator.NEQ,
    ">=",
    "<=",
    ">",
    "<",
    "=",
    "==",
    "!=",
}

_PRESENCE_OPERATORS = {
    Operator.DOCUMENT_REQUIRED,
    Operator.EXISTS,
    Operator.PRESENT,
    "DOCUMENT_REQUIRED",
    "EXISTS",
    "PRESENT",
    "IS_PRESENT",
}

_CATEGORICAL_OPERATORS = {
    Operator.EXACT,
    Operator.CONTAINS,
    Operator.EQUALS,
    Operator.EQ,
    Operator.NEQ,
    "EXACT",
    "CONTAINS",
    "=",
    "==",
    "!=",
}


class ComplianceEngine:
    """Deterministic evaluation engine matching requirements against bidder evidence."""

    def evaluate_requirement(
        self,
        requirement: Requirement,
        evidence: Optional[Union[Evidence, List[Evidence]]] = None,
        bidder_id: Optional[str] = None,
    ) -> ComplianceResult:
        """Evaluate a single requirement against provided evidence item(s).

        Args:
            requirement: Structured tender requirement.
            evidence: Single Evidence, list of Evidence items, or None.
            bidder_id: Optional identifier of the bidder.

        Returns:
            Deterministic ComplianceResult with traceable evidence provenance.
        """
        # 1. Handle missing evidence
        if evidence is None:
            evidence_list: List[Evidence] = []
        elif isinstance(evidence, Evidence):
            evidence_list = [evidence]
        else:
            evidence_list = [e for e in evidence if e is not None]

        if not evidence_list:
            param_desc = f" ({requirement.parameter})" if requirement.parameter else ""
            return ComplianceResult(
                requirement_id=requirement.requirement_id,
                bidder_id=bidder_id,
                status=ComplianceStatus.NEEDS_REVIEW,
                comparison="NO_EVIDENCE",
                explanation=(
                    f"No bidder evidence found for mandatory requirement "
                    f"'{requirement.requirement_id}'{param_desc}."
                ),
                confidence=1.0,
                evidence_ids=[],
            )

        # 2. Select primary evidence and collect all evidence IDs for provenance
        primary_evidence = evidence_list[0]
        all_evidence_ids = [e.evidence_id for e in evidence_list]

        # 3. Check for explicit missing/unfulfilled evidence indicator
        if primary_evidence.extracted_value is None and not primary_evidence.text.strip():
            return ComplianceResult(
                requirement_id=requirement.requirement_id,
                bidder_id=bidder_id,
                status=ComplianceStatus.NEEDS_REVIEW,
                comparison="EMPTY_EVIDENCE",
                explanation=f"Evidence text and extracted value are empty for requirement '{requirement.requirement_id}'.",
                confidence=1.0,
                evidence_ids=all_evidence_ids,
            )

        # 4. Check for explicit ambiguity flag on primary evidence
        if primary_evidence.is_ambiguous:
            return ComplianceResult(
                requirement_id=requirement.requirement_id,
                bidder_id=bidder_id,
                status=ComplianceStatus.NEEDS_REVIEW,
                comparison="AMBIGUOUS_EVIDENCE",
                explanation=(
                    f"Bidder evidence for requirement '{requirement.requirement_id}' "
                    f"is marked ambiguous or unverified: '{primary_evidence.text}'."
                ),
                confidence=primary_evidence.confidence or 0.5,
                evidence_ids=all_evidence_ids,
            )

        # 5. Check for partial evidence flag on primary evidence
        if primary_evidence.is_partial:
            return ComplianceResult(
                requirement_id=requirement.requirement_id,
                bidder_id=bidder_id,
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                comparison="PARTIAL_EVIDENCE",
                explanation=(
                    f"Bidder evidence only partially satisfies requirement '{requirement.requirement_id}': "
                    f"'{primary_evidence.text}'."
                ),
                confidence=primary_evidence.confidence or 0.8,
                evidence_ids=all_evidence_ids,
            )

        # 6. Dispatch based on operator and category
        op = requirement.operator
        cat = requirement.category

        # Presence/Document requirement dispatch
        if op in _PRESENCE_OPERATORS or cat == RequirementCategory.MANDATORY_DOCUMENT:
            result = evaluate_presence_requirement(requirement, primary_evidence, bidder_id)
            result.evidence_ids = all_evidence_ids
            return result

        # Numeric requirement dispatch (explicit numeric operator or numeric value with standard operator)
        if op in (">=", "<=", ">", "<", Operator.GTE, Operator.LTE, Operator.GT, Operator.LT):
            result = evaluate_numeric_requirement(requirement, primary_evidence, bidder_id)
            result.evidence_ids = all_evidence_ids
            return result

        if op in ("=", "==", Operator.EQ, Operator.EQUALS):
            # Check if required_value is numeric
            if isinstance(requirement.required_value, (int, float)) or (
                isinstance(requirement.required_value, str)
                and requirement.required_value.strip().replace(".", "", 1).isdigit()
            ):
                result = evaluate_numeric_requirement(requirement, primary_evidence, bidder_id)
            else:
                result = evaluate_categorical_requirement(requirement, primary_evidence, bidder_id)
            result.evidence_ids = all_evidence_ids
            return result

        # Categorical / String match dispatch
        if op in _CATEGORICAL_OPERATORS:
            result = evaluate_categorical_requirement(requirement, primary_evidence, bidder_id)
            result.evidence_ids = all_evidence_ids
            return result

        # Fallback when operator is unspecified
        if op is None:
            if isinstance(requirement.required_value, (int, float)):
                result = evaluate_numeric_requirement(requirement, primary_evidence, bidder_id)
            elif requirement.required_value is not None:
                result = evaluate_categorical_requirement(requirement, primary_evidence, bidder_id)
            else:
                result = evaluate_presence_requirement(requirement, primary_evidence, bidder_id)
            result.evidence_ids = all_evidence_ids
            return result

        # Unsupported operator
        return ComplianceResult(
            requirement_id=requirement.requirement_id,
            bidder_id=bidder_id,
            status=ComplianceStatus.NEEDS_REVIEW,
            comparison=None,
            explanation=f"Unsupported operator '{op}' for requirement '{requirement.requirement_id}'.",
            confidence=1.0,
            evidence_ids=all_evidence_ids,
        )

    def evaluate_bid(
        self,
        requirements: List[Requirement],
        evidence_items: List[Evidence],
        bidder_id: Optional[str] = None,
    ) -> List[ComplianceResult]:
        """Evaluate all tender requirements against the bidder's submitted evidence items.

        Args:
            requirements: List of structured requirements from tender document.
            evidence_items: List of all extracted evidence items from bidder documents.
            bidder_id: Optional bidder identifier.

        Returns:
            List of ComplianceResults, one for each requirement.
        """
        # Index evidence by requirement_id
        evidence_by_req: Dict[str, List[Evidence]] = {}
        for evi in evidence_items:
            if evi.requirement_id:
                evidence_by_req.setdefault(evi.requirement_id, []).append(evi)

        results: List[ComplianceResult] = []
        for req in requirements:
            matched_evidence = evidence_by_req.get(req.requirement_id, [])
            res = self.evaluate_requirement(req, matched_evidence, bidder_id=bidder_id)
            results.append(res)

        return results


# Global convenience function
_default_engine = ComplianceEngine()


def evaluate_requirement(
    requirement: Requirement,
    evidence: Optional[Union[Evidence, List[Evidence]]] = None,
    bidder_id: Optional[str] = None,
) -> ComplianceResult:
    """Evaluate a single requirement using the default deterministic engine."""
    return _default_engine.evaluate_requirement(requirement, evidence, bidder_id)


def evaluate_bid(
    requirements: List[Requirement],
    evidence_items: List[Evidence],
    bidder_id: Optional[str] = None,
) -> List[ComplianceResult]:
    """Evaluate all requirements for a bidder using the default deterministic engine."""
    return _default_engine.evaluate_bid(requirements, evidence_items, bidder_id)
