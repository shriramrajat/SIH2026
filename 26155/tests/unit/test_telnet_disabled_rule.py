"""
tests/unit/test_telnet_disabled_rule.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for TLN-001: Telnet Must Be Disabled
(:class:`src.compliance.rules.telnet_disabled.TelnetDisabledRule`)

Test IDs correspond to the requirements in the implementation brief:

  Cisco:
    C1.  transport input ssh                           -> PASS
    C2.  transport input none                          -> PASS
    C3.  transport input telnet                        -> FAIL
    C4.  transport input ssh telnet                    -> FAIL
    C5.  transport input all                           -> FAIL
    C6.  transport input unknown value                 -> NEEDS_REVIEW
    C7.  transport input absent from VTY section       -> NEEDS_REVIEW
    C8.  no VTY sections at all                        -> NEEDS_REVIEW
    C9.  multiple VTY sections all secure              -> PASS
    C10. first VTY secure + second VTY telnet          -> FAIL
    C11. transport output none + transport input ssh   -> PASS
    C12. global "no service telnet" alone must NOT produce PASS

  Juniper:
    J13. system with telnet;                           -> FAIL
    J14. system without telnet                         -> PASS
    J15. system section absent                         -> FAIL
    J16. ftp; present but no telnet                    -> PASS (not FAIL)
    J17. telnet flag evidence contains raw_line

  Vendor:
    V18. unsupported vendor                            -> NOT_APPLICABLE

  Evidence:
    E19. PASS has evidence
    E20. FAIL has evidence
    E21. NEEDS_REVIEW has evidence
    E22. Cisco FAIL evidence identifies offending VTY section name
    E23. multi-VTY FAIL identifies the specific offending section

  Remediation:
    R24. Cisco FAIL returns Cisco remediation only
    R25. Juniper FAIL returns Juniper remediation only
    R26. PASS returns no remediation

  Engine:
    EN27. audit() can evaluate SSH-001 and TLN-001 together in rule order
"""

import pytest

from src.compliance.engine import audit
from src.compliance.model import ComplianceStatus, Severity
from src.compliance.rules.ssh_version import SshVersionRule
from src.compliance.rules.telnet_disabled import TelnetDisabledRule
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
    return NormalizedConfig(vendor=vendor, hostname=None, raw_config="")


RULE = TelnetDisabledRule()

_VTY_BASE = "hostname R1\n"


def _cisco_vty(transport_line: str) -> NormalizedConfig:
    """Build a minimal Cisco config with a single VTY section."""
    raw = (
        _VTY_BASE
        + "line vty 0 4\n"
        + f" {transport_line}\n"
        + " login local\n"
    )
    return _cisco(raw)


# ---------------------------------------------------------------------------
# Cisco tests
# ---------------------------------------------------------------------------


class TestCiscoTelnetDisabled:

    def test_c1_transport_input_ssh_pass(self) -> None:
        """C1: transport input ssh -> PASS."""
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert result.status == ComplianceStatus.PASS

    def test_c2_transport_input_none_pass(self) -> None:
        """C2: transport input none -> PASS (no access at all)."""
        result = RULE.evaluate(_cisco_vty("transport input none"))
        assert result.status == ComplianceStatus.PASS

    def test_c3_transport_input_telnet_fail(self) -> None:
        """C3: transport input telnet -> FAIL."""
        result = RULE.evaluate(_cisco_vty("transport input telnet"))
        assert result.status == ComplianceStatus.FAIL

    def test_c4_transport_input_ssh_telnet_fail(self) -> None:
        """C4: transport input ssh telnet -> FAIL (telnet still allowed)."""
        result = RULE.evaluate(_cisco_vty("transport input ssh telnet"))
        assert result.status == ComplianceStatus.FAIL

    def test_c5_transport_input_all_fail(self) -> None:
        """C5: transport input all -> FAIL (all transports including Telnet)."""
        result = RULE.evaluate(_cisco_vty("transport input all"))
        assert result.status == ComplianceStatus.FAIL

    def test_c6_transport_input_unknown_needs_review(self) -> None:
        """C6: Unrecognised transport input value -> NEEDS_REVIEW."""
        config = NormalizedConfig(
            vendor="cisco",
            hostname="R1",
            sections=[
                ConfigSection(
                    name="line vty 0 4",
                    items=[
                        ConfigItem(
                            key="transport",
                            value="input rlogin",
                            raw_line=" transport input rlogin",
                        )
                    ],
                )
            ],
            raw_config="",
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c7_transport_input_absent_needs_review(self) -> None:
        """C7: VTY section with no transport input directive -> NEEDS_REVIEW."""
        raw = _VTY_BASE + "line vty 0 4\n login local\n"
        result = RULE.evaluate(_cisco(raw))
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c8_no_vty_sections_needs_review(self) -> None:
        """C8: No line vty sections at all -> NEEDS_REVIEW."""
        raw = _VTY_BASE + "ip domain-name lab.internal\n"
        result = RULE.evaluate(_cisco(raw))
        assert result.status == ComplianceStatus.NEEDS_REVIEW

    def test_c9_multiple_vty_sections_all_secure_pass(self) -> None:
        """C9: Multiple VTY ranges all configured ssh-only -> PASS."""
        raw = (
            _VTY_BASE
            + "line vty 0 4\n"
            + " transport input ssh\n"
            + "!\n"
            + "line vty 5 15\n"
            + " transport input ssh\n"
        )
        result = RULE.evaluate(_cisco(raw))
        assert result.status == ComplianceStatus.PASS

    def test_c10_first_vty_secure_second_vty_telnet_fail(self) -> None:
        """C10: One VTY range secure, another with telnet -> overall FAIL."""
        raw = (
            _VTY_BASE
            + "line vty 0 4\n"
            + " transport input ssh\n"
            + "!\n"
            + "line vty 5 15\n"
            + " transport input telnet\n"
        )
        result = RULE.evaluate(_cisco(raw))
        assert result.status == ComplianceStatus.FAIL

    def test_c11_transport_output_plus_input_ssh_pass(self) -> None:
        """C11: transport output none + transport input ssh -> PASS.

        'transport output' must NOT be mistaken for 'transport input'.
        Both have key='transport'; only the one whose value starts with
        'input' should be used for this control.
        """
        config = NormalizedConfig(
            vendor="cisco",
            hostname="R1",
            sections=[
                ConfigSection(
                    name="line vty 0 4",
                    items=[
                        ConfigItem(
                            key="transport",
                            value="output none",
                            raw_line=" transport output none",
                        ),
                        ConfigItem(
                            key="transport",
                            value="input ssh",
                            raw_line=" transport input ssh",
                        ),
                    ],
                )
            ],
            raw_config="",
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS, (
            "Rule incorrectly classified 'transport output none' as an "
            "input transport directive."
        )

    def test_c12_global_no_service_telnet_alone_not_pass(self) -> None:
        """C12: 'no service telnet' global directive alone must NOT produce PASS.

        Without any line vty section, the VTY transport policy is unknown.
        Expected: NEEDS_REVIEW (not PASS).
        """
        raw = (
            _VTY_BASE
            + "no service telnet\n"
            + "ip domain-name lab.internal\n"
        )
        result = RULE.evaluate(_cisco(raw))
        # Must not be PASS — global service command alone is insufficient.
        assert result.status != ComplianceStatus.PASS, (
            "Rule returned PASS based solely on 'no service telnet'. "
            "VTY transport must be the primary signal."
        )


# ---------------------------------------------------------------------------
# Juniper tests
# ---------------------------------------------------------------------------


class TestJuniperTelnetDisabled:

    def test_j13_system_with_telnet_fail(self) -> None:
        """J13: system section contains telnet; -> FAIL."""
        config = _juniper(
            "system {\n"
            "    host-name SRX-01;\n"
            "    services {\n"
            "        telnet;\n"
            "        ssh {\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j14_system_without_telnet_pass(self) -> None:
        """J14: system section exists but no telnet; -> PASS."""
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

    def test_j15_system_absent_fail(self) -> None:
        """J15: No system section at all -> FAIL."""
        config = _juniper(
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            '        description "WAN";\n'
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL

    def test_j16_ftp_present_no_telnet_pass(self) -> None:
        """J16: ftp; is present but no telnet; -> PASS (only telnet matters)."""
        config = _juniper(
            "system {\n"
            "    host-name SRX-01;\n"
            "    services {\n"
            "        ftp;\n"
            "        ssh {\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.PASS, (
            "Presence of ftp; incorrectly caused a FAIL for TLN-001."
        )

    def test_j17_telnet_flag_evidence_has_raw_line(self) -> None:
        """J17: When telnet; is present, evidence includes the raw_line."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        telnet;\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.evidence) >= 1
        ev = result.evidence[0]
        assert len(ev.raw_lines) >= 1
        assert "telnet" in ev.raw_lines[0].lower()


# ---------------------------------------------------------------------------
# Vendor applicability
# ---------------------------------------------------------------------------


class TestVendorApplicability:

    def test_v18_unsupported_vendor_not_applicable(self) -> None:
        """V18: Unsupported vendor -> NOT_APPLICABLE."""
        result = RULE.evaluate(_fake_vendor("arista"))
        assert result.status == ComplianceStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class TestEvidence:

    def test_e19_pass_has_evidence(self) -> None:
        """E19: PASS result includes at least one evidence record."""
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert result.status == ComplianceStatus.PASS
        assert len(result.evidence) >= 1

    def test_e20_fail_has_evidence(self) -> None:
        """E20: FAIL result includes at least one evidence record."""
        result = RULE.evaluate(_cisco_vty("transport input telnet"))
        assert result.status == ComplianceStatus.FAIL
        assert len(result.evidence) >= 1

    def test_e21_needs_review_has_evidence(self) -> None:
        """E21: NEEDS_REVIEW result includes at least one evidence record."""
        result = RULE.evaluate(_cisco((_VTY_BASE + "line vty 0 4\n login local\n")))
        assert result.status == ComplianceStatus.NEEDS_REVIEW
        assert len(result.evidence) >= 1

    def test_e22_cisco_fail_evidence_names_offending_vty_section(self) -> None:
        """E22: FAIL evidence section_name identifies the offending VTY section."""
        result = RULE.evaluate(_cisco_vty("transport input telnet"))
        assert result.status == ComplianceStatus.FAIL
        # At least one evidence record should name a line vty section.
        vty_evidence = [
            ev for ev in result.evidence
            if ev.section_name is not None
            and ev.section_name.lower().startswith("line vty")
        ]
        assert len(vty_evidence) >= 1, (
            "No evidence record identifies the offending VTY section."
        )

    def test_e23_multi_vty_fail_identifies_offending_section(self) -> None:
        """E23: With two VTY ranges, FAIL evidence pinpoints the bad range."""
        raw = (
            _VTY_BASE
            + "line vty 0 4\n"
            + " transport input ssh\n"
            + "!\n"
            + "line vty 5 15\n"
            + " transport input telnet\n"
        )
        result = RULE.evaluate(_cisco(raw))
        assert result.status == ComplianceStatus.FAIL

        # The offending section is 'line vty 5 15'.
        failing_ev = [
            ev for ev in result.evidence
            if ev.section_name == "line vty 5 15"
        ]
        assert len(failing_ev) >= 1, (
            "Evidence does not identify 'line vty 5 15' as the offending section."
        )
        # The passing section should also have evidence.
        passing_ev = [
            ev for ev in result.evidence
            if ev.section_name == "line vty 0 4"
        ]
        assert len(passing_ev) >= 1, (
            "Evidence for the passing section 'line vty 0 4' is missing."
        )

    def test_evidence_control_id_is_tln001(self) -> None:
        """Every evidence record carries the correct control_id."""
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        for ev in result.evidence:
            assert ev.control_id == "TLN-001"

    def test_not_applicable_has_evidence(self) -> None:
        """NOT_APPLICABLE result includes an explanatory evidence record."""
        result = RULE.evaluate(_fake_vendor("arista"))
        assert result.status == ComplianceStatus.NOT_APPLICABLE
        assert len(result.evidence) >= 1
        assert result.evidence[0].note != ""

    def test_juniper_pass_absence_evidence_empty_raw_lines(self) -> None:
        """Juniper PASS: absence evidence has empty raw_lines."""
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
        # For absence evidence, raw_lines should be empty.
        assert all(ev.raw_lines == () for ev in result.evidence)


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class TestRemediation:

    def test_r24_cisco_fail_returns_cisco_remediation_only(self) -> None:
        """R24: FAIL on Cisco -> only Cisco remediation returned."""
        result = RULE.evaluate(_cisco_vty("transport input telnet"))
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "cisco"

    def test_r25_juniper_fail_returns_juniper_remediation_only(self) -> None:
        """R25: FAIL on Juniper -> only Juniper remediation returned."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        telnet;\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.status == ComplianceStatus.FAIL
        assert len(result.remediations) == 1
        assert result.remediations[0].vendor == "juniper"

    def test_r26_pass_returns_no_remediation(self) -> None:
        """R26: PASS -> remediations list is empty."""
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert result.status == ComplianceStatus.PASS
        assert result.remediations == []

    def test_r26_juniper_pass_returns_no_remediation(self) -> None:
        """R26 (Juniper): PASS -> remediations list is empty."""
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
        result = RULE.evaluate(_cisco_vty("transport input telnet"))
        assert result.remediations[0].config_hint is not None

    def test_juniper_remediation_has_config_hint(self) -> None:
        """Juniper remediation includes a config_hint."""
        config = _juniper(
            "system {\n"
            "    services {\n"
            "        telnet;\n"
            "    }\n"
            "}\n"
        )
        result = RULE.evaluate(config)
        assert result.remediations[0].config_hint is not None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TestEngine:

    def test_en27_audit_ssh001_and_tln001_together_in_order(self) -> None:
        """EN27: audit() evaluates SSH-001 and TLN-001 together, in order."""
        config = _cisco(
            "hostname SEC-ROUTER\n"
            "ip ssh version 2\n"
            "line vty 0 4\n"
            " transport input ssh\n"
            " login local\n"
        )
        ssh_rule = SshVersionRule()
        tln_rule = TelnetDisabledRule()
        results = audit(config, [ssh_rule, tln_rule])

        assert len(results) == 2
        assert results[0].control_id == "SSH-001"
        assert results[1].control_id == "TLN-001"
        assert results[0].status == ComplianceStatus.PASS
        assert results[1].status == ComplianceStatus.PASS

    def test_en27_mixed_pass_fail_ordering_preserved(self) -> None:
        """EN27 (order): FAIL on TLN-001 does not affect SSH-001 result."""
        config = _cisco(
            "hostname R1\n"
            "ip ssh version 2\n"
            "line vty 0 4\n"
            " transport input telnet\n"
        )
        ssh_rule = SshVersionRule()
        tln_rule = TelnetDisabledRule()
        results = audit(config, [ssh_rule, tln_rule])

        assert results[0].control_id == "SSH-001"
        assert results[0].status == ComplianceStatus.PASS   # SSH is v2
        assert results[1].control_id == "TLN-001"
        assert results[1].status == ComplianceStatus.FAIL   # Telnet allowed


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestResultMetadata:

    def test_control_id_is_tln001(self) -> None:
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert result.control_id == "TLN-001"

    def test_severity_is_critical(self) -> None:
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert result.severity == Severity.CRITICAL

    def test_framework_refs_present(self) -> None:
        result = RULE.evaluate(_cisco_vty("transport input ssh"))
        assert len(result.framework_refs) > 0

    def test_vendor_propagated(self) -> None:
        c = RULE.evaluate(_cisco_vty("transport input ssh"))
        j = RULE.evaluate(
            _juniper(
                "system {\n    services {\n        ssh {\n"
                "            protocol-version v2;\n        }\n    }\n}\n"
            )
        )
        assert c.vendor == "cisco"
        assert j.vendor == "juniper"

    def test_hostname_propagated(self) -> None:
        result = RULE.evaluate(_cisco("hostname MY-ROUTER\nline vty 0 4\n transport input ssh\n"))
        assert result.hostname == "MY-ROUTER"
