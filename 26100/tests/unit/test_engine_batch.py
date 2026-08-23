"""Unit tests running batch evaluation on the synthetic benchmark dataset."""

from src.compliance.engine import ComplianceEngine, evaluate_bid
from src.compliance.models import ComplianceStatus


def test_batch_synthetic_tender_evaluation(
    engine,
    synthetic_requirements,
    synthetic_evidence,
    expected_outcomes,
):
    """Verify that batch evaluation over the entire synthetic suite matches expected outcomes."""
    results = engine.evaluate_bid(
        requirements=synthetic_requirements,
        evidence_items=synthetic_evidence,
        bidder_id="BIDDER-ALPHA",
    )

    assert len(results) == len(synthetic_requirements)

    results_by_req = {res.requirement_id: res for res in results}

    for req_id, expected_status in expected_outcomes.items():
        assert req_id in results_by_req, f"Requirement {req_id} missing from results"
        actual_result = results_by_req[req_id]
        assert actual_result.bidder_id == "BIDDER-ALPHA"
        assert (
            actual_result.status == expected_status
        ), f"Mismatch for {req_id}: expected {expected_status}, got {actual_result.status}. Explanation: {actual_result.explanation}"

        # If compliant or non-compliant, must have evidence provenance
        if actual_result.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT):
            assert len(actual_result.evidence_ids) > 0


def test_convenience_evaluate_bid_function(
    synthetic_requirements,
    synthetic_evidence,
    expected_outcomes,
):
    """Test top-level evaluate_bid function behaves identically."""
    results = evaluate_bid(
        requirements=synthetic_requirements,
        evidence_items=synthetic_evidence,
        bidder_id="BIDDER-BETA",
    )
    for res in results:
        expected = expected_outcomes[res.requirement_id]
        assert res.status == expected
