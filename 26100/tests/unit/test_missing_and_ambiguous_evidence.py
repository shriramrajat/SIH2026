"""Unit tests verifying that missing, empty, or ambiguous evidence yields conservative review states."""

import pytest
from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestMissingAndAmbiguousEvidence:
    """Test suite ensuring the engine never invents values or assumes compliance."""

    def test_none_evidence_yields_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-MISSING-01",
            original_text="3 years experience required.",
            parameter="experience",
            operator=Operator.GTE,
            required_value=3,
            unit="years",
        )
        res = engine.evaluate_requirement(req, evidence=None)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert res.comparison == "NO_EVIDENCE"
        assert "No bidder evidence found" in res.explanation
        assert res.evidence_ids == []

    def test_empty_evidence_list_yields_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-MISSING-02",
            original_text="ISO 9001 certificate required.",
            operator=Operator.DOCUMENT_REQUIRED,
        )
        res = engine.evaluate_requirement(req, evidence=[])
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert res.comparison == "NO_EVIDENCE"
        assert res.evidence_ids == []

    def test_empty_evidence_content_yields_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-EMPTY-01",
            original_text="RAM >= 16 GB",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-BLANK",
            text="   ",
            extracted_value=None,
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert res.comparison == "EMPTY_EVIDENCE"

    def test_ambiguous_evidence_flag_yields_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-AMBIG-01",
            original_text="Annual Turnover >= 50 Lakhs",
            parameter="turnover",
            operator=Operator.GTE,
            required_value=50,
            unit="Lakhs",
        )
        evi = Evidence(
            evidence_id="EVID-AMBIG",
            text="Turnover is roughly between 40 and 60 Lakhs (unverified).",
            extracted_value=None,
            is_ambiguous=True,
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert "ambiguous or unverified" in res.explanation

    def test_partial_evidence_flag_yields_partially_compliant(self, engine):
        req = Requirement(
            requirement_id="REQ-PARTIAL-01",
            original_text="3 Client References required",
            operator=Operator.DOCUMENT_REQUIRED,
        )
        evi = Evidence(
            evidence_id="EVID-PART",
            text="Attached 1 reference letter.",
            is_partial=True,
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.status == ComplianceStatus.PARTIALLY_COMPLIANT
        assert res.comparison == "PARTIAL_EVIDENCE"

    def test_unsupported_operator_yields_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-UNKNOWN-OP",
            original_text="Some complex fuzzy clause",
            operator="FUZZY_MATCH_APPROX",
            required_value="something",
        )
        evi = Evidence(
            evidence_id="EVID-UNSUPP",
            text="Some evidence snippet",
            extracted_value="something",
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert "Unsupported operator" in res.explanation
