"""Unit tests for core Pydantic domain models."""

import pytest
from pydantic import ValidationError
from src.compliance.models import ComplianceResult, ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement, RequirementCategory


class TestRequirementModel:
    """Tests for Requirement model schema and validation."""

    def test_valid_requirement_instantiation(self):
        req = Requirement(
            requirement_id="REQ-001",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="RAM must be at least 16 GB.",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
            mandatory=True,
            source_document="tender.pdf",
            page=10,
            extraction_confidence=0.95,
        )
        assert req.requirement_id == "REQ-001"
        assert req.operator == Operator.GTE
        assert req.required_value == 16
        assert req.unit == "GB"
        assert req.page == 10
        assert req.extraction_confidence == 0.95

    def test_requirement_defaults(self):
        req = Requirement(
            requirement_id="REQ-002",
            original_text="Mandatory GST certificate required.",
        )
        assert req.category == RequirementCategory.TECHNICAL_SPECIFICATION
        assert req.mandatory is True
        assert req.operator is None
        assert req.required_value is None

    def test_requirement_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            Requirement(
                requirement_id="REQ-003",
                original_text="Test",
                invalid_extra_field="disallowed",
            )

    def test_requirement_confidence_range_validation(self):
        with pytest.raises(ValidationError):
            Requirement(
                requirement_id="REQ-004",
                original_text="Test",
                extraction_confidence=1.5,  # > 1.0 is invalid
            )
        with pytest.raises(ValidationError):
            Requirement(
                requirement_id="REQ-005",
                original_text="Test",
                extraction_confidence=-0.1,  # < 0.0 is invalid
            )

    def test_requirement_json_serialization(self):
        req = Requirement(
            requirement_id="REQ-JSON",
            original_text="SSD >= 512 GB",
            operator=Operator.GTE,
            required_value=512,
            unit="GB",
        )
        json_data = req.model_dump_json()
        assert "REQ-JSON" in json_data
        assert "512" in json_data


class TestEvidenceModel:
    """Tests for Evidence model schema and validation."""

    def test_valid_evidence_instantiation(self):
        evi = Evidence(
            evidence_id="EVID-001",
            requirement_id="REQ-001",
            document_id="bid_doc.pdf",
            page=3,
            section="Specs",
            text="Memory: 32 GB DDR4",
            extracted_value=32,
            unit="GB",
            confidence=0.99,
        )
        assert evi.evidence_id == "EVID-001"
        assert evi.requirement_id == "REQ-001"
        assert evi.extracted_value == 32
        assert evi.unit == "GB"
        assert evi.is_contradictory is False

    def test_evidence_flags(self):
        evi = Evidence(
            evidence_id="EVID-002",
            text="Certificate expired in 2023.",
            is_contradictory=True,
            is_partial=False,
            is_ambiguous=False,
        )
        assert evi.is_contradictory is True
        assert evi.is_partial is False

    def test_evidence_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            Evidence(
                evidence_id="EVID-003",
                text="Some text",
                unknown_attribute="not_allowed",
            )


class TestComplianceResultModel:
    """Tests for ComplianceResult model schema and validation."""

    def test_valid_compliance_result(self):
        res = ComplianceResult(
            requirement_id="REQ-001",
            bidder_id="BIDDER-100",
            status=ComplianceStatus.COMPLIANT,
            comparison="32 GB >= 16 GB",
            explanation="Required ram >= 16 GB; bidder evidence reports 32 GB.",
            confidence=1.0,
            evidence_ids=["EVID-001"],
        )
        assert res.requirement_id == "REQ-001"
        assert res.status == ComplianceStatus.COMPLIANT
        assert res.evidence_ids == ["EVID-001"]

    def test_allowed_compliance_states(self):
        allowed = {"COMPLIANT", "NON_COMPLIANT", "PARTIALLY_COMPLIANT", "NEEDS_REVIEW"}
        enum_values = {status.value for status in ComplianceStatus}
        assert enum_values == allowed

    def test_invalid_compliance_status_raises(self):
        with pytest.raises(ValidationError):
            ComplianceResult(
                requirement_id="REQ-001",
                status="POSSIBLY_COMPLIANT",  # Invalid state
                explanation="Testing invalid state",
            )
