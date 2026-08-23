"""Unit tests for document and certificate presence requirements."""

import pytest
from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement, RequirementCategory


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestDocumentPresence:
    """Test suite for document and certificate presence checks."""

    def test_document_present_compliant(self, engine):
        req = Requirement(
            requirement_id="REQ-DOC-01",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="Valid ISO 9001:2015 certificate required.",
            parameter="iso_9001",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="ISO 9001:2015 Certificate",
        )
        evi = Evidence(
            evidence_id="EVID-DOC-01",
            requirement_id="REQ-DOC-01",
            document_id="iso_cert.pdf",
            page=1,
            text="ISO 9001:2015 Registration Certificate QMS-12345.",
            extracted_value="ISO 9001:2015 Valid Certificate",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert "verified" in res.explanation
        assert "document 'iso_cert.pdf'" in res.explanation
        assert res.evidence_ids == ["EVID-DOC-01"]

    def test_document_contradictory_or_expired_fails(self, engine):
        req = Requirement(
            requirement_id="REQ-DOC-02",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="Active ISO 27001 certificate required.",
            parameter="iso_27001",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="ISO 27001 Certificate",
        )
        evi = Evidence(
            evidence_id="EVID-DOC-02",
            requirement_id="REQ-DOC-02",
            document_id="iso27001_audit.pdf",
            page=1,
            text="ISO 27001 certificate was revoked on 2024-05-10.",
            is_contradictory=True,
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NON_COMPLIANT
        assert "invalid or contradictory" in res.explanation

    def test_document_partial_submission(self, engine):
        req = Requirement(
            requirement_id="REQ-DOC-03",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="Submit 3 client reference letters.",
            parameter="client_letters",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="3 Letters",
        )
        evi = Evidence(
            evidence_id="EVID-DOC-03",
            requirement_id="REQ-DOC-03",
            text="Only 1 letter submitted.",
            is_partial=True,
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.PARTIALLY_COMPLIANT
        assert "partially" in res.explanation.lower()

    def test_document_ambiguous_submission(self, engine):
        req = Requirement(
            requirement_id="REQ-DOC-04",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="CA audited balance sheet required.",
            parameter="audited_balance_sheet",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="Audited Balance Sheet",
        )
        evi = Evidence(
            evidence_id="EVID-DOC-04",
            requirement_id="REQ-DOC-04",
            text="Unsigned draft spreadsheet without CA registration number.",
            is_ambiguous=True,
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert "ambiguous or unverified" in res.explanation
