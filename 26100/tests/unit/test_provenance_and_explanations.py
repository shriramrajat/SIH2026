"""Unit tests verifying evidence provenance and factual explanations."""

import pytest
from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestProvenanceAndExplanations:
    """Test suite ensuring exact traceability of decisions to source documents/pages."""

    def test_single_evidence_provenance_tracked(self, engine):
        req = Requirement(
            requirement_id="REQ-PROV-01",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-PROV-999",
            requirement_id="REQ-PROV-01",
            document_id="technical_bid_vol1.pdf",
            page=15,
            section="Memory Specs",
            text="Installed RAM is 32 GB.",
            extracted_value=32,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.evidence_ids == ["EVID-PROV-999"]
        assert "technical_bid_vol1.pdf" in res.explanation
        assert "page 15" in res.explanation

    def test_multiple_evidence_ids_retained(self, engine):
        req = Requirement(
            requirement_id="REQ-MULTI-PROV",
            original_text="OEM Authorization certificate required.",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="OEM Authorization",
        )
        evi1 = Evidence(
            evidence_id="EVID-101",
            requirement_id="REQ-MULTI-PROV",
            document_id="oem_letter_p1.pdf",
            page=1,
            text="OEM authorization letter part 1",
            extracted_value="OEM Letter",
        )
        evi2 = Evidence(
            evidence_id="EVID-102",
            requirement_id="REQ-MULTI-PROV",
            document_id="oem_letter_p2.pdf",
            page=2,
            text="OEM authorization signatures",
            extracted_value="OEM Signatures",
        )
        res = engine.evaluate_requirement(req, evidence=[evi1, evi2])
        assert res.status == ComplianceStatus.COMPLIANT
        assert set(res.evidence_ids) == {"EVID-101", "EVID-102"}

    def test_no_fictional_explanation(self, engine):
        req = Requirement(
            requirement_id="REQ-FACT-01",
            original_text="Storage >= 512 GB",
            parameter="storage",
            operator=Operator.GTE,
            required_value=512,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-FACT-01",
            document_id="spec_sheet.pdf",
            page=4,
            text="Installed drive: 256 GB SSD",
            extracted_value=256,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evidence=evi)
        assert res.status == ComplianceStatus.NON_COMPLIANT
        # Verify explanation strictly reflects actual numbers and source document
        assert "Required storage >= 512 GB" in res.explanation
        assert "256 GB" in res.explanation
        assert "spec_sheet.pdf" in res.explanation
        assert "page 4" in res.explanation
