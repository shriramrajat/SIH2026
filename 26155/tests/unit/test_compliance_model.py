"""
tests/unit/test_compliance_model.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the compliance model dataclasses and enumerations.
(:mod:`src.compliance.model`)
"""

import pytest

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Remediation,
    Severity,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_all_values_present(self) -> None:
        names = {s.name for s in Severity}
        assert names == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_value_strings(self) -> None:
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"


# ---------------------------------------------------------------------------
# ComplianceStatus
# ---------------------------------------------------------------------------


class TestComplianceStatus:
    def test_all_values_present(self) -> None:
        names = {s.name for s in ComplianceStatus}
        assert names == {"PASS", "FAIL", "NOT_APPLICABLE", "NEEDS_REVIEW"}

    def test_value_strings(self) -> None:
        assert ComplianceStatus.PASS.value == "pass"
        assert ComplianceStatus.FAIL.value == "fail"
        assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"
        assert ComplianceStatus.NEEDS_REVIEW.value == "needs_review"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_construct_with_raw_lines(self) -> None:
        e = Evidence(
            control_id="SSH-001",
            section_name=None,
            raw_lines=("ip ssh version 2",),
            observed="ssh version 2",
            expected="ssh version 2",
            note="Found SSH version 2.",
        )
        assert e.control_id == "SSH-001"
        assert e.raw_lines == ("ip ssh version 2",)
        assert e.observed == "ssh version 2"
        assert e.note == "Found SSH version 2."

    def test_absence_evidence_has_empty_raw_lines(self) -> None:
        e = Evidence(
            control_id="SSH-001",
            section_name=None,
            raw_lines=(),
            observed=None,
            expected="ip ssh version 2",
            note="Directive was absent.",
        )
        assert e.raw_lines == ()
        assert e.observed is None

    def test_is_immutable(self) -> None:
        e = Evidence(
            control_id="SSH-001",
            section_name=None,
            raw_lines=(),
            observed=None,
            expected=None,
            note="test",
        )
        with pytest.raises((AttributeError, TypeError)):
            e.note = "changed"  # type: ignore[misc]

    def test_section_name_can_be_none(self) -> None:
        e = Evidence(
            control_id="SSH-001",
            section_name=None,
            raw_lines=(),
            observed=None,
            expected=None,
            note="n/a",
        )
        assert e.section_name is None

    def test_section_name_can_be_string(self) -> None:
        e = Evidence(
            control_id="SSH-001",
            section_name="system",
            raw_lines=("    protocol-version v2;",),
            observed="v2",
            expected="v2",
            note="Found under system.",
        )
        assert e.section_name == "system"


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class TestRemediation:
    def test_construct_with_hint(self) -> None:
        r = Remediation(
            vendor="cisco",
            guidance="Add ip ssh version 2.",
            config_hint="ip ssh version 2",
        )
        assert r.vendor == "cisco"
        assert r.config_hint == "ip ssh version 2"

    def test_config_hint_optional(self) -> None:
        r = Remediation(vendor="any", guidance="Review SSH settings.")
        assert r.config_hint is None

    def test_is_immutable(self) -> None:
        r = Remediation(vendor="cisco", guidance="Do something.")
        with pytest.raises((AttributeError, TypeError)):
            r.vendor = "juniper"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ComplianceResult
# ---------------------------------------------------------------------------


class TestComplianceResult:
    def _make_result(self, status: ComplianceStatus) -> ComplianceResult:
        return ComplianceResult(
            control_id="SSH-001",
            control_name="SSH Protocol Version",
            description="SSH must use version 2.",
            severity=Severity.HIGH,
            status=status,
            vendor="cisco",
            hostname="LAB-ROUTER-01",
            evidence=[],
            remediations=[],
            framework_refs=["CIS-IOS-L2-1.1.1"],
        )

    def test_construct_pass_result(self) -> None:
        r = self._make_result(ComplianceStatus.PASS)
        assert r.status == ComplianceStatus.PASS
        assert r.vendor == "cisco"
        assert r.hostname == "LAB-ROUTER-01"

    def test_framework_refs_is_list(self) -> None:
        r = self._make_result(ComplianceStatus.PASS)
        assert isinstance(r.framework_refs, list)

    def test_evidence_defaults_to_empty_list(self) -> None:
        r = ComplianceResult(
            control_id="SSH-001",
            control_name="SSH Protocol Version",
            description="desc",
            severity=Severity.HIGH,
            status=ComplianceStatus.NOT_APPLICABLE,
            vendor="other",
            hostname=None,
        )
        assert r.evidence == []
        assert r.remediations == []
        assert r.framework_refs == []

    def test_hostname_can_be_none(self) -> None:
        r = self._make_result(ComplianceStatus.FAIL)
        r2 = ComplianceResult(
            control_id="SSH-001",
            control_name="SSH Protocol Version",
            description="desc",
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            vendor="cisco",
            hostname=None,
        )
        assert r2.hostname is None
