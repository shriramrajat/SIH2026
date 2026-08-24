"""
tests/unit/test_ssh_version_rule.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for SSH-001: SSH Protocol Version
(:class:`src.compliance.rules.ssh_version.SshVersionRule`)

Test IDs correspond to the requirements in the implementation brief:

  Cisco:
    C1.  SSH version 2 present                            -> PASS
    C2.  SSH version 1 present                            -> FAIL
    C3.  SSH version directive absent                     -> FAIL
    C4.  Multiple ip-prefixed directives; SSH v2 is not
         the first ip item                                -> PASS
    C5.  Unexpected SSH version value                     -> NEEDS_REVIEW

  Juniper:
    J6.  protocol-version v2                              -> PASS
    J7.  protocol-version v1                              -> FAIL
    J8.  SSH configuration absent (no protocol-version)   -> FAIL
    J9.  system section absent entirely                   -> FAIL
    J10. Unexpected protocol-version value                -> NEEDS_REVIEW

  Vendor applicability:
    V11. Unsupported vendor                               -> NOT_APPLICABLE

  Evidence:
    E12. PASS result includes evidence
    E13. FAIL result includes evidence
    E14. Missing config produces absence evidence (empty raw_lines)
    E15. Evidence contains raw_line when ConfigItem exists

  Remediation:
    R16. FAIL on Cisco returns Cisco remediation only
    R17. FAIL on Juniper returns Juniper remediation only
    R18. PASS returns no remediation

  Engine:
    EN19. audit() evaluates all supplied rules
    EN20. audit() returns results in rule order
"""

import pytest

from src.compliance.engine import audit
from src.compliance.model import ComplianceStatus, Severity
from src.compliance.rules.ssh_version import SshVersionRule
from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cisco(raw: str) -> NormalizedConfig:
    return parse_cisco(raw)


def _juniper(raw: str) -> NormalizedConfig:
    return parse_juniper(raw)


def _fake_vendor(vendor: str) -> NormalizedConfig:
    """Return a minimal NormalizedConfig for an unsupported vendor."""
    return NormalizedConfig(
        vendor=vendor,
        hostname=None,
        raw_config="",
    )


RULE = SshVersionRule()


# ---------------------------------------------------------------------------
# Cisco tests
# ---------------------------------------------------------------------------


class TestCiscoSshVersion:

    def test_c1_ssh_version_2_pass(self) -> None:
        """C1: 'ip ssh version 2' present -> PASS."""
        config = _cisco("hostname R1\nip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_c2_ssh_version_1_fail(self) -> None:
        """C2: 'ip ssh version 1' present -> FAIL."""
        config = _cisco("hostname R1\nip ssh version 1\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c3_ssh_version_absent_fail(self) -> None:
        """C3: No SSH version directive -> FAIL."""
        config = _cisco("hostname R1\nip domain-name lab.internal\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_c4_ssh_v2_not_first_ip_item_pass(self) -> None:
        """C4: Multiple 'ip ...' directives; SSH v2 is NOT the first -> PASS.

        get_global('ip') would return 'ip domain-name', not the SSH directive.
        The rule must still find SSH v2 by scanning all ip-keyed items.
        """
        config = _cisco(
            "hostname R1\n"
            "ip domain-name lab.internal\n"       # first ip item
            "ip ssh version 2\n"                   # NOT the first ip item
            "ip ssh time-out 60\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS, (
            "Rule returned {} instead of PASS. "
            "get_global('ip') returns 'domain-name lab.internal'; "
            "rule must scan all ip-keyed global items.".format(result.status)
        )

    def test_c5_unexpected_ssh_value_needs_review(self) -> None:
        """C5: SSH version directive with unrecognised value -> NEEDS_REVIEW."""
        # Inject a synthetic item that the Cisco parser wouldn't normally produce
        # but that a future parser extension or an unusual IOS variant might.
        config = NormalizedConfig(
            vendor="cisco",
            hostname="R1",
            global_items=[
                ConfigItem(
                    key="ip",
                    value="ssh version default",
                    raw_line="ip ssh version default",
                )
            ],
            raw_config="ip ssh version default\n",
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Juniper tests
# ---------------------------------------------------------------------------


class TestJuniperSshVersion:

    def test_j6_protocol_version_v2_pass(self) -> None:
        """J6: protocol-version v2 -> PASS."""
        config = _juniper(
            "system {\n"
            "    host-name SRX-01;\n"
            "    services {\n"
            "        ssh {\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS

    def test_j7_protocol_version_v1_fail(self) -> None:
        """J7: protocol-version v1 -> FAIL."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        ssh {\n"
            "            protocol-version v1;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j8_ssh_config_absent_fail(self) -> None:
        """J8: system section present but no protocol-version -> FAIL."""
        config = _juniper(
            "system {\n"
            "    host-name SRX-01;\n"
            "    time-zone UTC;\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j9_system_section_absent_fail(self) -> None:
        """J9: No system section at all -> FAIL."""
        config = _juniper(
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        description \"WAN\";\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j10_unexpected_protocol_value_needs_review(self) -> None:
        """J10: protocol-version with unrecognised value -> NEEDS_REVIEW."""
        config = NormalizedConfig(
            vendor="juniper",
            hostname="SRX-01",
            sections=[
                ConfigSection(
                    name="system",
                    items=[
                        ConfigItem(
                            key="protocol-version",
                            value="tls",
                            raw_line="            protocol-version tls;",
                        )
                    ],
                )
            ],
            raw_config="",
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Vendor applicability
# ---------------------------------------------------------------------------


class TestVendorApplicability:

    def test_v11_unsupported_vendor_not_applicable(self) -> None:
        """V11: Unsupported vendor -> NOT_APPLICABLE."""
        config = _fake_vendor("arista")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Evidence quality
# ---------------------------------------------------------------------------


class TestEvidence:

    def test_e12_pass_includes_evidence(self) -> None:
        """E12: PASS result always includes at least one evidence record."""
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS
        assert len(result.evidence) >= 1

    def test_e13_fail_includes_evidence(self) -> None:
        """E13: FAIL result always includes at least one evidence record."""
        config = _cisco("hostname R1\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.evidence) >= 1

    def test_e14_absent_config_produces_empty_raw_lines(self) -> None:
        """E14: When directive is absent, evidence.raw_lines is empty."""
        config = _cisco("hostname R1\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        ev = result.evidence[0]
        assert ev.raw_lines == ()

    def test_e15_present_item_raw_line_in_evidence(self) -> None:
        """E15: When a ConfigItem exists, its raw_line appears in evidence."""
        config = _cisco("hostname R1\nip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS
        ev = result.evidence[0]
        assert len(ev.raw_lines) >= 1
        assert "ip ssh version 2" in ev.raw_lines[0]

    def test_e15_juniper_raw_line_in_evidence(self) -> None:
        """E15 (Juniper): raw_line appears in evidence when item exists."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        ssh {\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS
        ev = result.evidence[0]
        assert len(ev.raw_lines) >= 1
        assert "protocol-version" in ev.raw_lines[0]

    def test_evidence_has_control_id(self) -> None:
        """Every evidence record carries the correct control_id."""
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        for ev in result.evidence:
            assert ev.control_id == "SSH-001"

    def test_not_applicable_includes_evidence(self) -> None:
        """NOT_APPLICABLE result still carries an explanatory evidence record."""
        config = _fake_vendor("arista")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.NOT_APPLICABLE
        assert len(result.evidence) >= 1
        assert result.evidence[0].note != ""


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class TestRemediation:

    def test_r16_cisco_fail_returns_cisco_remediation_only(self) -> None:
        """R16: FAIL on Cisco -> only Cisco remediation returned."""
        config = _cisco("hostname R1\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "cisco"

    def test_r17_juniper_fail_returns_juniper_remediation_only(self) -> None:
        """R17: FAIL on Juniper -> only Juniper remediation returned."""
        config = _juniper("system {\n    time-zone UTC;\n}\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "juniper"

    def test_r18_pass_returns_no_remediation(self) -> None:
        """R18: PASS -> remediations list is empty."""
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS
        assert result.remediations == []

    def test_r18_juniper_pass_returns_no_remediation(self) -> None:
        """R18 (Juniper): PASS -> remediations list is empty."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        ssh {\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS
        assert result.remediations == []

    def test_cisco_remediation_has_config_hint(self) -> None:
        """Cisco remediation includes a config_hint."""
        config = _cisco("hostname R1\n")
        result = RULE.evaluate(config)
        assert result.remediations[0].config_hint is not None

    def test_juniper_remediation_has_config_hint(self) -> None:
        """Juniper remediation includes a config_hint."""
        config = _juniper("system {\n    time-zone UTC;\n}\n")
        result = RULE.evaluate(config)
        assert result.remediations[0].config_hint is not None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TestEngine:

    def test_en19_audit_evaluates_all_rules(self) -> None:
        """EN19: audit() evaluates every supplied rule."""
        config = _cisco("ip ssh version 2\n")
        results = audit(config, [RULE, RULE])
        assert len(results) == 2

    def test_en20_audit_preserves_rule_order(self) -> None:
        """EN20: audit() returns results in the same order as the rule list."""

        class _AlwaysPass(SshVersionRule):
            def evaluate(self, cfg):
                from src.compliance.model import ComplianceResult, ComplianceStatus, Severity
                return ComplianceResult(
                    control_id="DUMMY-PASS",
                    control_name="Always Pass",
                    description="test",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    vendor=cfg.vendor,
                    hostname=cfg.hostname,
                )

        class _AlwaysFail(SshVersionRule):
            def evaluate(self, cfg):
                from src.compliance.model import ComplianceResult, ComplianceStatus, Severity
                return ComplianceResult(
                    control_id="DUMMY-FAIL",
                    control_name="Always Fail",
                    description="test",
                    severity=Severity.INFO,
                    status=ComplianceStatus.FAIL,
                    vendor=cfg.vendor,
                    hostname=cfg.hostname,
                )

        config = _cisco("hostname R1\n")
        results = audit(config, [_AlwaysPass(), _AlwaysFail()])
        assert results[0].control_id == "DUMMY-PASS"
        assert results[1].control_id == "DUMMY-FAIL"
        assert results[0].status == ComplianceStatus.PASS
        assert results[1].status == ComplianceStatus.FAIL

    def test_en19_audit_empty_rules_returns_empty_list(self) -> None:
        """EN19 edge: audit() with no rules returns an empty list."""
        config = _cisco("hostname R1\n")
        results = audit(config, [])
        assert results == []

    def test_en19_audit_not_applicable_included_in_results(self) -> None:
        """EN19: NOT_APPLICABLE results are included (not silently dropped)."""
        config = _fake_vendor("arista")
        results = audit(config, [RULE])
        assert len(results) == 1
        assert results[0].status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# ComplianceResult metadata
# ---------------------------------------------------------------------------


class TestResultMetadata:

    def test_control_id_is_ssh001(self) -> None:
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.control_id == "SSH-001"

    def test_severity_is_high(self) -> None:
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.severity == Severity.HIGH

    def test_framework_refs_present(self) -> None:
        config = _cisco("ip ssh version 2\n")
        result = RULE.evaluate(config)
        assert len(result.framework_refs) > 0

    def test_vendor_matches_config(self) -> None:
        c_result = RULE.evaluate(_cisco("ip ssh version 2\n"))
        j_result = RULE.evaluate(
            _juniper("system {\n    services {\n        ssh {\n            protocol-version v2;\n        }\n    }\n}\n")
        )
        assert c_result.vendor == "cisco"
        assert j_result.vendor == "juniper"

    def test_hostname_propagated(self) -> None:
        config = _cisco("hostname MY-ROUTER\nip ssh version 2\n")
        result = RULE.evaluate(config)
        assert result.hostname == "MY-ROUTER"
