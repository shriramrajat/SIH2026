"""Unit tests for deterministic numeric comparisons and unit conversions."""

import pytest
from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement


@pytest.fixture
def engine():
    return ComplianceEngine()


class TestNumericComparisons:
    """Test suite for numeric operators (>=, <=, >, <, ==, !=)."""

    def test_greater_than_or_equal_pass(self, engine):
        req = Requirement(
            requirement_id="REQ-GTE-01",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-GTE-01",
            requirement_id="REQ-GTE-01",
            document_id="spec.pdf",
            page=2,
            text="Installed RAM: 32 GB",
            extracted_value=32,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert "32 GB >= 16 GB" in res.comparison
        assert "Required ram >= 16 GB; bidder evidence reports 32 GB" in res.explanation
        assert res.evidence_ids == ["EVID-GTE-01"]

    def test_greater_than_or_equal_exact_boundary(self, engine):
        req = Requirement(
            requirement_id="REQ-GTE-02",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-GTE-02",
            requirement_id="REQ-GTE-02",
            text="Installed RAM: 16 GB",
            extracted_value=16,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert res.comparison == "16 GB >= 16 GB"

    def test_greater_than_or_equal_fail(self, engine):
        req = Requirement(
            requirement_id="REQ-GTE-03",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-GTE-03",
            requirement_id="REQ-GTE-03",
            text="Installed RAM: 8 GB",
            extracted_value=8,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NON_COMPLIANT
        assert "8 GB >= 16 GB" in res.comparison

    def test_less_than_or_equal_pass(self, engine):
        req = Requirement(
            requirement_id="REQ-LTE-01",
            original_text="Response time <= 4 hours",
            parameter="response_time",
            operator=Operator.LTE,
            required_value=4,
            unit="hours",
        )
        evi = Evidence(
            evidence_id="EVID-LTE-01",
            requirement_id="REQ-LTE-01",
            text="Response time: 2 hours",
            extracted_value=2,
            unit="hours",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert res.comparison == "2 hours <= 4 hours"

    def test_less_than_or_equal_fail(self, engine):
        req = Requirement(
            requirement_id="REQ-LTE-02",
            original_text="Response time <= 4 hours",
            parameter="response_time",
            operator=Operator.LTE,
            required_value=4,
            unit="hours",
        )
        evi = Evidence(
            evidence_id="EVID-LTE-02",
            requirement_id="REQ-LTE-02",
            text="Response time: 6 hours",
            extracted_value=6,
            unit="hours",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NON_COMPLIANT

    def test_strict_greater_than(self, engine):
        req = Requirement(
            requirement_id="REQ-GT-01",
            original_text="Years in business > 5 years",
            parameter="experience",
            operator=Operator.GT,
            required_value=5,
            unit="years",
        )
        evi_pass = Evidence(
            evidence_id="EVID-GT-PASS",
            text="Operating for 6 years",
            extracted_value=6,
            unit="years",
        )
        evi_boundary = Evidence(
            evidence_id="EVID-GT-FAIL",
            text="Operating for 5 years",
            extracted_value=5,
            unit="years",
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_boundary).status == ComplianceStatus.NON_COMPLIANT

    def test_strict_less_than(self, engine):
        req = Requirement(
            requirement_id="REQ-LT-01",
            original_text="Downtime < 1 hour",
            parameter="downtime",
            operator=Operator.LT,
            required_value=1,
            unit="hours",
        )
        evi_pass = Evidence(
            evidence_id="EVID-LT-PASS",
            text="Downtime: 0.5 hours",
            extracted_value=0.5,
            unit="hours",
        )
        evi_boundary = Evidence(
            evidence_id="EVID-LT-FAIL",
            text="Downtime: 1 hour",
            extracted_value=1,
            unit="hours",
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_boundary).status == ComplianceStatus.NON_COMPLIANT

    def test_numeric_equality_pass_and_fail(self, engine):
        req = Requirement(
            requirement_id="REQ-EQ-01",
            original_text="Display size = 15.6 inches",
            parameter="display_size",
            operator=Operator.EQ,
            required_value=15.6,
            unit="inches",
        )
        evi_pass = Evidence(
            evidence_id="EVID-EQ-PASS",
            text="Display: 15.6 inches",
            extracted_value=15.6,
            unit="inches",
        )
        evi_fail = Evidence(
            evidence_id="EVID-EQ-FAIL",
            text="Display: 14 inches",
            extracted_value=14,
            unit="inches",
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_fail).status == ComplianceStatus.NON_COMPLIANT


class TestUnitConversions:
    """Test suite for unit conversion and normalization."""

    def test_digital_storage_conversion_pass(self, engine):
        req = Requirement(
            requirement_id="REQ-UNIT-01",
            original_text="Storage >= 1 TB",
            parameter="storage",
            operator=Operator.GTE,
            required_value=1,
            unit="TB",
        )
        evi = Evidence(
            evidence_id="EVID-UNIT-01",
            requirement_id="REQ-UNIT-01",
            text="Storage capacity: 2048 GB",
            extracted_value=2048,
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert "2 TB >= 1 TB" in res.comparison

    def test_time_unit_conversion(self, engine):
        req = Requirement(
            requirement_id="REQ-UNIT-TIME",
            original_text="Response time <= 1 day",
            parameter="response_time",
            operator=Operator.LTE,
            required_value=1,
            unit="days",
        )
        evi = Evidence(
            evidence_id="EVID-UNIT-TIME",
            text="Response time: 12 hours",
            extracted_value=12,
            unit="hours",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.COMPLIANT
        assert "0.5 days <= 1 days" in res.comparison

    def test_currency_and_multiples_conversion(self, engine):
        req = Requirement(
            requirement_id="REQ-FIN-01",
            original_text="Turnover >= 1 Crore",
            parameter="turnover",
            operator=Operator.GTE,
            required_value=1,
            unit="Crore",
        )
        evi_pass = Evidence(
            evidence_id="EVID-FIN-PASS",
            text="Turnover: 150 Lakhs",
            extracted_value=150,
            unit="Lakhs",
        )
        evi_fail = Evidence(
            evidence_id="EVID-FIN-FAIL",
            text="Turnover: 75 Lakhs",
            extracted_value=75,
            unit="Lakhs",
        )
        assert engine.evaluate_requirement(req, evi_pass).status == ComplianceStatus.COMPLIANT
        assert engine.evaluate_requirement(req, evi_fail).status == ComplianceStatus.NON_COMPLIANT

    def test_incompatible_units_returns_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-UNIT-INCOMPAT",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-UNIT-INCOMPAT",
            text="Weight: 16 kg",
            extracted_value=16,
            unit="kg",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert "Incompatible or ambiguous units" in res.explanation

    def test_non_numeric_evidence_value_returns_needs_review(self, engine):
        req = Requirement(
            requirement_id="REQ-NON-NUM",
            original_text="RAM >= 16 GB",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
        )
        evi = Evidence(
            evidence_id="EVID-NON-NUM",
            text="High memory capacity installed",
            extracted_value="high",
            unit="GB",
        )
        res = engine.evaluate_requirement(req, evi)
        assert res.status == ComplianceStatus.NEEDS_REVIEW
        assert "does not contain a parseable numeric value" in res.explanation
