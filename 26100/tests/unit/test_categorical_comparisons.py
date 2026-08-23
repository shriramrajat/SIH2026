"""Unit tests for categorical equality and string matching requirements."""

import pytest
from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement, RequirementCategory


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestCategoricalComparisons:
    """Test suite for categorical operators and text matching."""

    def test_exact_match_pass(self, engine):
        req = Requirement(
            requirement_id="REQ-CAT-01",
            category=RequirementCategory.ELIGIBILITY,
            original_text="Bidder must be Class 1 Local Supplier.",
            parameter="mii_class",
            operator=Operator.EQUALS,
            required_value="Class 1",
        )
        evi = Evidence(
            evidence_id="EVID-CAT-01",
            requirement_id="REQ-CAT-01",
            document_id="mii_decl.pdf",
            page=1,
            text="We declare our status as Class 1 Local Supplier.",
            extracted_value="Class 1",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert "matches 'Class 1'" in res.explanation
        assert res.evidence_ids == ["EVID-CAT-01"]

    def test_case_insensitive_and_whitespace_trimming(self, engine):
        req = Requirement(
            requirement_id="REQ-CAT-02",
            original_text="OS: Ubuntu 22.04 LTS",
            parameter="os",
            operator=Operator.EQUALS,
            required_value="Ubuntu 22.04 LTS",
        )
        evi = Evidence(
            evidence_id="EVID-CAT-02",
            requirement_id="REQ-CAT-02",
            text="OS:  ubuntu 22.04 lts  ",
            extracted_value="  ubuntu 22.04 lts  ",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT

    def test_categorical_mismatch_fails(self, engine):
        req = Requirement(
            requirement_id="REQ-CAT-03",
            original_text="Make in India: Class 1",
            parameter="mii_class",
            operator=Operator.EQUALS,
            required_value="Class 1",
        )
        evi = Evidence(
            evidence_id="EVID-CAT-03",
            requirement_id="REQ-CAT-03",
            text="Bidder is Class 2 Local Supplier.",
            extracted_value="Class 2",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NON_COMPLIANT
        assert "reports 'Class 2'" in res.explanation

    def test_contains_operator(self, engine):
        req = Requirement(
            requirement_id="REQ-CAT-CONTAINS",
            original_text="Processor family must include Xeon Gold",
            parameter="cpu_family",
            operator=Operator.CONTAINS,
            required_value="xeon gold",
        )
        evi_pass = Evidence(
            evidence_id="EVID-CONT-PASS",
            text="Intel Xeon Gold 6330 Processor installed",
            extracted_value="Intel Xeon Gold 6330 Processor",
        )
        evi_fail = Evidence(
            evidence_id="EVID-CONT-FAIL",
            text="Intel Core i9-13900K",
            extracted_value="Intel Core i9-13900K",
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_fail).status == ComplianceStatus.NON_COMPLIANT

    def test_boolean_equivalence(self, engine):
        req = Requirement(
            requirement_id="REQ-BOOL",
            original_text="Energy Star Certified",
            parameter="energy_star",
            operator=Operator.EQUALS,
            required_value=True,
        )
        evi_pass = Evidence(
            evidence_id="EVID-BOOL-PASS",
            text="Energy Star: Yes",
            extracted_value=True,
        )
        evi_fail = Evidence(
            evidence_id="EVID-BOOL-FAIL",
            text="Energy Star: No",
            extracted_value=False,
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_fail).status == ComplianceStatus.NON_COMPLIANT
