"""
tests/unit/test_compliance_engine.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the compliance engine (:func:`src.compliance.engine.audit`).

Tests verify:
- one result per rule, in order
- a crashing rule does NOT abort evaluation of subsequent rules
- the error result has status NEEDS_REVIEW and preserves the exception message
- a well-formed audit produces the expected statuses
"""

from __future__ import annotations

import pytest

from src.compliance.engine import audit
from src.compliance.model import ComplianceResult, ComplianceStatus, Severity
from src.compliance.rules.base import ComplianceRule, SecurityControl
from src.normalization.model import NormalizedConfig


# ---------------------------------------------------------------------------
# Minimal helpers / test doubles
# ---------------------------------------------------------------------------


def _make_config(vendor: str = "cisco") -> NormalizedConfig:
    """Return a minimal NormalizedConfig for testing."""
    return NormalizedConfig(vendor=vendor, hostname="TEST-HOST")


def _make_control(control_id: str = "TEST-001") -> SecurityControl:
    return SecurityControl(
        control_id=control_id,
        control_name=f"Test Rule {control_id}",
        description="A test rule.",
        severity=Severity.LOW,
        framework_refs=(),
        applicable_vendors=frozenset({"*"}),
    )


class _PassRule(ComplianceRule):
    """Stub rule that always passes."""

    control = _make_control("PASS-001")

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        return self._build_result(
            config=config,
            status=ComplianceStatus.PASS,
            evidence=[],
        )


class _FailRule(ComplianceRule):
    """Stub rule that always fails."""

    control = _make_control("FAIL-001")

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        return self._build_result(
            config=config,
            status=ComplianceStatus.FAIL,
            evidence=[],
        )


class _CrashRule(ComplianceRule):
    """Stub rule that always raises a RuntimeError."""

    control = _make_control("CRASH-001")

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        raise RuntimeError("Intentional crash for testing engine isolation")


class _NotApplicableRule(ComplianceRule):
    """Stub rule that always returns NOT_APPLICABLE."""

    control = SecurityControl(
        control_id="NA-001",
        control_name="Not Applicable Rule",
        description="Never applicable.",
        severity=Severity.INFO,
        framework_refs=(),
        applicable_vendors=frozenset(),  # no vendor matches
    )

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        return self._not_applicable(config)


# ---------------------------------------------------------------------------
# Tests: basic contract
# ---------------------------------------------------------------------------


class TestAuditBasicContract:
    """The engine's basic output contract."""

    def test_returns_list(self) -> None:
        """audit() always returns a list."""
        config = _make_config()
        result = audit(config, [])
        assert isinstance(result, list)

    def test_empty_rules_returns_empty_list(self) -> None:
        """No rules → empty result list."""
        assert audit(_make_config(), []) == []

    def test_one_result_per_rule(self) -> None:
        """The number of results equals the number of rules."""
        rules = [_PassRule(), _FailRule(), _NotApplicableRule()]
        results = audit(_make_config(), rules)
        assert len(results) == len(rules)

    def test_result_order_matches_rule_order(self) -> None:
        """Results are returned in the same order as the rules list."""
        rules = [_PassRule(), _FailRule()]
        results = audit(_make_config(), rules)
        assert results[0].control_id == "PASS-001"
        assert results[1].control_id == "FAIL-001"

    def test_each_result_is_compliance_result(self) -> None:
        """Every element in the returned list is a ComplianceResult."""
        results = audit(_make_config(), [_PassRule(), _FailRule()])
        for r in results:
            assert isinstance(r, ComplianceResult)

    def test_vendor_propagated_to_results(self) -> None:
        """The vendor from the config is reflected in each result."""
        config = _make_config(vendor="cisco")
        results = audit(config, [_PassRule()])
        assert results[0].vendor == "cisco"


# ---------------------------------------------------------------------------
# Tests: exception isolation
# ---------------------------------------------------------------------------


class TestAuditExceptionIsolation:
    """A crashing rule must not prevent other rules from running."""

    def test_crashing_rule_does_not_raise(self) -> None:
        """audit() does not propagate exceptions from rules."""
        config = _make_config()
        # Should NOT raise:
        results = audit(config, [_CrashRule()])
        assert len(results) == 1

    def test_crashing_rule_produces_needs_review(self) -> None:
        """A crashing rule produces a NEEDS_REVIEW result."""
        config = _make_config()
        results = audit(config, [_CrashRule()])
        assert results[0].status == ComplianceStatus.NEEDS_REVIEW

    def test_crashing_rule_preserves_control_id(self) -> None:
        """The error result preserves the control_id from the crashing rule."""
        config = _make_config()
        results = audit(config, [_CrashRule()])
        assert results[0].control_id == "CRASH-001"

    def test_crashing_rule_evidence_contains_exception_message(self) -> None:
        """The exception message appears in the evidence note."""
        config = _make_config()
        results = audit(config, [_CrashRule()])
        assert len(results[0].evidence) == 1
        note = results[0].evidence[0].note
        assert "Intentional crash for testing engine isolation" in note

    def test_rules_after_crashing_rule_still_run(self) -> None:
        """Rules after a crashing rule are not skipped."""
        rules = [_PassRule(), _CrashRule(), _FailRule()]
        results = audit(_make_config(), rules)
        assert len(results) == 3
        assert results[0].status == ComplianceStatus.PASS
        assert results[1].status == ComplianceStatus.NEEDS_REVIEW  # crash
        assert results[2].status == ComplianceStatus.FAIL

    def test_rules_before_crashing_rule_still_pass(self) -> None:
        """Rules before a crashing rule are unaffected."""
        rules = [_FailRule(), _CrashRule()]
        results = audit(_make_config(), rules)
        assert results[0].status == ComplianceStatus.FAIL
        assert results[1].status == ComplianceStatus.NEEDS_REVIEW

    def test_multiple_crashing_rules_all_produce_results(self) -> None:
        """Multiple crashing rules each produce their own error result."""
        rules = [_CrashRule(), _CrashRule()]
        results = audit(_make_config(), rules)
        assert len(results) == 2
        for r in results:
            assert r.status == ComplianceStatus.NEEDS_REVIEW

    def test_crash_result_traceback_in_note(self) -> None:
        """The error result's note contains traceback text for debuggability."""
        results = audit(_make_config(), [_CrashRule()])
        note = results[0].evidence[0].note
        # Traceback text always contains "Traceback" header
        assert "Traceback" in note or "RuntimeError" in note
