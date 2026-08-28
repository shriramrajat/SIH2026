"""
tests/integration/test_pipeline.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Integration tests for the full 26155 compliance scanner pipeline:

    raw configuration text
        ↓
    detect_vendor()
        ↓
    parse_cisco() / parse_juniper()
        ↓
    audit(config, RULE_REGISTRY)
        ↓
    list[ComplianceResult]

Key properties verified
-----------------------
- The real fixture files are used (no mocking, no constructed ConfigItems).
- Vendor detection is exercised end-to-end.
- Parser output feeds directly into the compliance engine.
- The result list contains the expected number of results (one per rule).
- Vendor and hostname are correctly propagated through the pipeline.
- Expected compliance statuses for the canonical fixtures are asserted
  (these are regression anchors — if a rule changes its expected output for
  the fixture config, this test catches it).

Fixture configs
---------------
cisco-basic.conf  — SSH v2 set, VTY SSH-only, no telnet, no AAA
juniper-basic.conf — SSH v2 set, no telnet service, has system section
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.compliance.engine import audit
from src.compliance.model import ComplianceResult, ComplianceStatus
from src.compliance.registry import RULE_REGISTRY
from src.ingestion.detector import detect_vendor
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper

FIXTURES = Path(__file__).parent.parent / "fixtures"
CISCO_FIXTURE = FIXTURES / "cisco-basic.conf"
JUNIPER_FIXTURE = FIXTURES / "juniper-basic.conf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _result_by_id(results: list[ComplianceResult], control_id: str) -> ComplianceResult:
    """Return the result for *control_id* from *results*, or raise."""
    for r in results:
        if r.control_id == control_id:
            return r
    raise KeyError(f"No result found for control_id={control_id!r}")


# ---------------------------------------------------------------------------
# Cisco pipeline integration
# ---------------------------------------------------------------------------


class TestCiscoPipeline:
    """Full pipeline integration tests using the Cisco fixture."""

    @pytest.fixture(scope="class")
    def cisco_results(self) -> list[ComplianceResult]:
        raw = _load(CISCO_FIXTURE)
        vendor = detect_vendor(raw)
        config = parse_cisco(raw)
        config.source_file = str(CISCO_FIXTURE)
        return audit(config, RULE_REGISTRY)

    # ── Detection ──────────────────────────────────────────────────────────

    def test_cisco_fixture_detected_as_cisco(self) -> None:
        """Vendor detection correctly identifies the Cisco fixture."""
        raw = _load(CISCO_FIXTURE)
        assert detect_vendor(raw) == "cisco"

    # ── Pipeline output contract ───────────────────────────────────────────

    def test_returns_one_result_per_rule(self, cisco_results: list) -> None:
        """The pipeline returns exactly one result for each registered rule."""
        assert len(cisco_results) == len(RULE_REGISTRY)

    def test_all_results_are_compliance_results(self, cisco_results: list) -> None:
        """Every element in the result list is a ComplianceResult."""
        for r in cisco_results:
            assert isinstance(r, ComplianceResult)

    def test_vendor_is_cisco_in_all_results(self, cisco_results: list) -> None:
        """All results carry vendor='cisco'."""
        for r in cisco_results:
            assert r.vendor == "cisco"

    def test_hostname_propagated(self, cisco_results: list) -> None:
        """Hostname from the fixture is propagated to every result."""
        for r in cisco_results:
            assert r.hostname == "LAB-ROUTER-01"

    # ── Rule-specific status assertions for the canonical Cisco fixture ────

    def test_ssh_version_passes_for_cisco_fixture(self, cisco_results: list) -> None:
        """SSH-001 must PASS: cisco-basic.conf has 'ip ssh version 2'."""
        r = _result_by_id(cisco_results, "SSH-001")
        assert r.status == ComplianceStatus.PASS, (
            f"SSH-001 expected PASS, got {r.status.value}. "
            f"Evidence: {[e.note for e in r.evidence]}"
        )

    def test_telnet_disabled_passes_for_cisco_fixture(self, cisco_results: list) -> None:
        """TLN-001 must PASS: VTY uses 'transport input ssh'."""
        r = _result_by_id(cisco_results, "TLN-001")
        assert r.status == ComplianceStatus.PASS, (
            f"TLN-001 expected PASS, got {r.status.value}. "
            f"Evidence: {[e.note for e in r.evidence]}"
        )

    def test_exec_timeout_needs_review_for_cisco_fixture(self, cisco_results: list) -> None:
        """EXEC-001: cisco-basic.conf has no exec-timeout → NEEDS_REVIEW."""
        r = _result_by_id(cisco_results, "EXEC-001")
        assert r.status == ComplianceStatus.NEEDS_REVIEW, (
            f"EXEC-001 expected NEEDS_REVIEW, got {r.status.value}."
        )

    def test_pwd_encryption_needs_review_for_cisco_fixture(self, cisco_results: list) -> None:
        """PWD-001: cisco-basic.conf has no 'enable' directive → NEEDS_REVIEW."""
        r = _result_by_id(cisco_results, "PWD-001")
        assert r.status == ComplianceStatus.NEEDS_REVIEW, (
            f"PWD-001 expected NEEDS_REVIEW, got {r.status.value}."
        )

    def test_aaa_fails_for_cisco_fixture(self, cisco_results: list) -> None:
        """AAA-001: cisco-basic.conf has no 'aaa new-model' → FAIL."""
        r = _result_by_id(cisco_results, "AAA-001")
        assert r.status == ComplianceStatus.FAIL, (
            f"AAA-001 expected FAIL, got {r.status.value}."
        )

    # ── Evidence quality ───────────────────────────────────────────────────

    def test_passing_results_have_evidence(self, cisco_results: list) -> None:
        """Even PASS results must contain evidence (traceability requirement)."""
        ssh = _result_by_id(cisco_results, "SSH-001")
        assert len(ssh.evidence) > 0

    def test_failing_results_have_remediation(self, cisco_results: list) -> None:
        """FAIL results must carry at least one remediation."""
        aaa = _result_by_id(cisco_results, "AAA-001")
        assert len(aaa.remediations) > 0

    def test_source_file_preserved_in_config(self) -> None:
        """source_file is correctly attached to the NormalizedConfig."""
        raw = _load(CISCO_FIXTURE)
        config = parse_cisco(raw)
        config.source_file = str(CISCO_FIXTURE)
        assert config.source_file == str(CISCO_FIXTURE)


# ---------------------------------------------------------------------------
# Juniper pipeline integration
# ---------------------------------------------------------------------------


class TestJuniperPipeline:
    """Full pipeline integration tests using the Juniper fixture."""

    @pytest.fixture(scope="class")
    def juniper_results(self) -> list[ComplianceResult]:
        raw = _load(JUNIPER_FIXTURE)
        vendor = detect_vendor(raw)
        config = parse_juniper(raw)
        config.source_file = str(JUNIPER_FIXTURE)
        return audit(config, RULE_REGISTRY)

    # ── Detection ──────────────────────────────────────────────────────────

    def test_juniper_fixture_detected_as_juniper(self) -> None:
        """Vendor detection correctly identifies the Juniper fixture."""
        raw = _load(JUNIPER_FIXTURE)
        assert detect_vendor(raw) == "juniper"

    # ── Pipeline output contract ───────────────────────────────────────────

    def test_returns_one_result_per_rule(self, juniper_results: list) -> None:
        assert len(juniper_results) == len(RULE_REGISTRY)

    def test_vendor_is_juniper_in_all_results(self, juniper_results: list) -> None:
        for r in juniper_results:
            assert r.vendor == "juniper"

    def test_hostname_propagated(self, juniper_results: list) -> None:
        for r in juniper_results:
            assert r.hostname == "LAB-SRX-01"

    # ── Rule-specific status assertions for the canonical Juniper fixture ──

    def test_ssh_version_passes_for_juniper_fixture(self, juniper_results: list) -> None:
        """SSH-001 must PASS: juniper-basic.conf has 'protocol-version v2;'."""
        r = _result_by_id(juniper_results, "SSH-001")
        assert r.status == ComplianceStatus.PASS, (
            f"SSH-001 expected PASS, got {r.status.value}. "
            f"Evidence: {[e.note for e in r.evidence]}"
        )

    def test_telnet_disabled_passes_for_juniper_fixture(self, juniper_results: list) -> None:
        """TLN-001 must PASS: juniper-basic.conf has no 'telnet;' service."""
        r = _result_by_id(juniper_results, "TLN-001")
        assert r.status == ComplianceStatus.PASS, (
            f"TLN-001 expected PASS, got {r.status.value}. "
            f"Evidence: {[e.note for e in r.evidence]}"
        )

    def test_exec_timeout_needs_review_for_juniper_fixture(self, juniper_results: list) -> None:
        """EXEC-001: juniper-basic.conf has no idle-timeout → NEEDS_REVIEW."""
        r = _result_by_id(juniper_results, "EXEC-001")
        assert r.status == ComplianceStatus.NEEDS_REVIEW, (
            f"EXEC-001 expected NEEDS_REVIEW, got {r.status.value}."
        )

    def test_aaa_fails_for_juniper_fixture(self, juniper_results: list) -> None:
        """AAA-001: juniper-basic.conf has no authentication-order → FAIL."""
        r = _result_by_id(juniper_results, "AAA-001")
        assert r.status == ComplianceStatus.FAIL, (
            f"AAA-001 expected FAIL, got {r.status.value}."
        )

    # ── Evidence quality ───────────────────────────────────────────────────

    def test_passing_results_have_evidence(self, juniper_results: list) -> None:
        ssh = _result_by_id(juniper_results, "SSH-001")
        assert len(ssh.evidence) > 0
        # The evidence raw_lines must reference the actual source line.
        assert len(ssh.evidence[0].raw_lines) > 0

    def test_failing_results_have_remediation(self, juniper_results: list) -> None:
        aaa = _result_by_id(juniper_results, "AAA-001")
        assert len(aaa.remediations) > 0


# ---------------------------------------------------------------------------
# Cross-vendor: unknown vendor returns NOT_APPLICABLE for vendor-specific rules
# ---------------------------------------------------------------------------


class TestUnknownVendorPipeline:
    """Rules with specific vendor sets return NOT_APPLICABLE for unknown vendors."""

    def test_ssh_rule_not_applicable_for_unknown_vendor(self) -> None:
        """SSH-001 applies to cisco+juniper — NOT_APPLICABLE for unknown."""
        from src.compliance.rules.ssh_version import SshVersionRule
        from src.normalization.model import NormalizedConfig

        config = NormalizedConfig(vendor="unknown", hostname=None)
        result = SshVersionRule().evaluate(config)
        assert result.status == ComplianceStatus.NOT_APPLICABLE

    def test_all_rules_handle_unknown_vendor_without_crash(self) -> None:
        """No rule should crash when given vendor='unknown'."""
        from src.normalization.model import NormalizedConfig

        config = NormalizedConfig(vendor="unknown", hostname=None)
        results = audit(config, RULE_REGISTRY)
        assert len(results) == len(RULE_REGISTRY)
        # All should be NOT_APPLICABLE or NEEDS_REVIEW; none should be an engine-error crash
        for r in results:
            assert r.status in (
                ComplianceStatus.NOT_APPLICABLE,
                ComplianceStatus.NEEDS_REVIEW,
            ), f"Rule {r.control_id} returned unexpected status {r.status} for unknown vendor"
