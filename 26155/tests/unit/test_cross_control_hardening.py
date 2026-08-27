"""Cross-control and result-contract regression tests for 26155."""

from __future__ import annotations

import pytest

from src.compliance.engine import audit
from src.compliance.model import ComplianceStatus
from src.compliance.rules.aaa import AaaRule
from src.compliance.rules.exec_timeout import ExecTimeoutRule
from src.compliance.rules.pwd_encryption import PwdEncryptionRule
from src.compliance.rules.ssh_version import SshVersionRule
from src.compliance.rules.telnet_disabled import TelnetDisabledRule
from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper


RULES = [SshVersionRule(), TelnetDisabledRule(), ExecTimeoutRule(), PwdEncryptionRule(), AaaRule()]


def _cisco(text: str) -> NormalizedConfig:
    return parse_cisco(text)


def _juniper(text: str) -> NormalizedConfig:
    return parse_juniper(text)


def _statuses(config: NormalizedConfig) -> dict[str, ComplianceStatus]:
    return {result.control_id: result.status for result in audit(config, RULES)}


def _assert_contract(config: NormalizedConfig, expected: dict[str, ComplianceStatus]) -> None:
    results = audit(config, RULES)
    assert {result.control_id: result.status for result in results} == expected
    for result in results:
        assert result.control_name
        assert result.description
        assert result.severity
        assert result.vendor == config.vendor
        assert result.hostname == config.hostname
        assert result.evidence
        assert all(evidence.control_id == result.control_id for evidence in result.evidence)
        assert result.framework_refs
        if result.status == ComplianceStatus.PASS:
            assert result.remediations == []
        elif result.status == ComplianceStatus.FAIL:
            assert len(result.remediations) == 1
            assert result.remediations[0].vendor == config.vendor
        else:
            assert result.remediations == []


def test_cisco_fully_compliant_all_controls_pass() -> None:
    config = _cisco(
        "hostname R1\n"
        "ip ssh version 2\n"
        "enable secret 9 $9$hash\n"
        "aaa new-model\n"
        "aaa authentication login default group radius local\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " exec-timeout 10 0\n"
    )
    _assert_contract(config, {control.control.control_id: ComplianceStatus.PASS for control in RULES})


def test_cisco_single_control_failure_is_isolated() -> None:
    config = _cisco(
        "hostname R1\n"
        "ip ssh version 1\n"
        "enable secret 9 $9$hash\n"
        "aaa new-model\n"
        "aaa authentication login default group radius\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " exec-timeout 10 0\n"
    )
    assert _statuses(config) == {
        "SSH-001": ComplianceStatus.FAIL,
        "TLN-001": ComplianceStatus.PASS,
        "EXEC-001": ComplianceStatus.PASS,
        "PWD-001": ComplianceStatus.PASS,
        "AAA-001": ComplianceStatus.PASS,
    }


def test_cisco_multiple_failures_do_not_cross_contaminate() -> None:
    config = _cisco(
        "hostname R1\n"
        "ip ssh version 1\n"
        "enable password cleartext\n"
        "aaa new-model\n"
        "aaa authentication login default local\n"
        "line vty 0 4\n"
        " transport input telnet\n"
        " exec-timeout 0 0\n"
    )
    assert _statuses(config) == {
        "SSH-001": ComplianceStatus.FAIL,
        "TLN-001": ComplianceStatus.FAIL,
        "EXEC-001": ComplianceStatus.FAIL,
        "PWD-001": ComplianceStatus.FAIL,
        "AAA-001": ComplianceStatus.FAIL,
    }


def test_cisco_missing_sections_and_malformed_directives_are_explicit() -> None:
    config = _cisco(
        "hostname R1\n"
        "ip ssh version unknown\n"
        "enable unknown format\n"
        "aaa new-model\n"
        "aaa authentication login default kerberos\n"
        "line vty 0 4\n"
        " transport input rlogin\n"
        " exec-timeout malformed\n"
    )
    assert _statuses(config) == {
        "SSH-001": ComplianceStatus.NEEDS_REVIEW,
        "TLN-001": ComplianceStatus.NEEDS_REVIEW,
        "EXEC-001": ComplianceStatus.NEEDS_REVIEW,
        "PWD-001": ComplianceStatus.NEEDS_REVIEW,
        "AAA-001": ComplianceStatus.NEEDS_REVIEW,
    }


def test_cisco_multiple_vty_sections_are_evaluated_independently() -> None:
    config = _cisco(
        "hostname R1\n"
        "ip ssh version 2\n"
        "enable secret 9 $9$hash\n"
        "aaa new-model\n"
        "aaa authentication login default group radius\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " exec-timeout 10 0\n"
        "line vty 5 15\n"
        " transport input telnet\n"
        " exec-timeout 0 0\n"
    )
    statuses = _statuses(config)
    assert statuses["SSH-001"] == ComplianceStatus.PASS
    assert statuses["TLN-001"] == ComplianceStatus.FAIL
    assert statuses["EXEC-001"] == ComplianceStatus.FAIL
    assert statuses["PWD-001"] == ComplianceStatus.PASS
    assert statuses["AAA-001"] == ComplianceStatus.PASS


def test_juniper_fully_compliant_all_controls_pass() -> None:
    config = _juniper(
        "system {\n"
        " host-name SRX-1;\n"
        " authentication-order [ radius password ];\n"
        " encrypted-password \"$6$hash\";\n"
        " services {\n"
        "  ssh {\n"
        "   protocol-version v2;\n"
        "  }\n"
        " }\n"
        " login {\n"
        "  idle-timeout 10;\n"
        " }\n"
        "}\n"
    )
    _assert_contract(config, {control.control.control_id: ComplianceStatus.PASS for control in RULES})


def test_juniper_missing_system_is_handled_per_control() -> None:
    config = _juniper("interfaces { ge-0/0/0 { disable; } }\n")
    statuses = _statuses(config)
    assert statuses["SSH-001"] == ComplianceStatus.FAIL
    assert statuses["TLN-001"] == ComplianceStatus.FAIL
    assert statuses["EXEC-001"] == ComplianceStatus.NEEDS_REVIEW
    assert statuses["PWD-001"] == ComplianceStatus.NEEDS_REVIEW
    assert statuses["AAA-001"] == ComplianceStatus.FAIL


def test_juniper_multiple_auth_and_password_entries_are_isolated() -> None:
    config = NormalizedConfig(
        vendor="juniper",
        hostname="SRX-1",
        sections=[
            ConfigSection(
                name="system",
                items=[
                    ConfigItem("protocol-version", "v2", "protocol-version v2;"),
                    ConfigItem("authentication-order", "[ radius password ]", "authentication-order [ radius password ];"),
                    ConfigItem("authentication-order", "[ password radius ]", "authentication-order [ password radius ];"),
                    ConfigItem("encrypted-password", '"$6$one"', 'encrypted-password "$6$one";'),
                    ConfigItem("encrypted-password", '"$1$two"', 'encrypted-password "$1$two";'),
                    ConfigItem("telnet", None, "telnet;"),
                    ConfigItem("idle-timeout", "10", "idle-timeout 10;"),
                ],
            )
        ],
    )
    statuses = _statuses(config)
    assert statuses["AAA-001"] == ComplianceStatus.PASS
    assert statuses["PWD-001"] == ComplianceStatus.FAIL
    assert statuses["TLN-001"] == ComplianceStatus.FAIL


def test_unsupported_vendor_is_not_applicable_without_remediation() -> None:
    config = NormalizedConfig(vendor="arista", hostname="A1")
    results = audit(config, RULES)
    assert all(result.status == ComplianceStatus.NOT_APPLICABLE for result in results)
    assert all(result.remediations == [] for result in results)


def test_cisco_malformed_password_value_never_exposes_raw_line() -> None:
    config = NormalizedConfig(
        vendor="cisco",
        hostname="R1",
        global_items=[ConfigItem("enable", None, "enable password SuperSecret123")],
    )
    result = PwdEncryptionRule().evaluate(config)
    assert result.status == ComplianceStatus.NEEDS_REVIEW
    assert "SuperSecret123" not in str(result.evidence)


def test_juniper_empty_password_value_never_exposes_raw_line() -> None:
    config = NormalizedConfig(
        vendor="juniper",
        hostname="J1",
        sections=[
            ConfigSection(
                "system",
                [ConfigItem("encrypted-password", None, 'encrypted-password "$6$SecretHash";')],
            )
        ],
    )
    result = PwdEncryptionRule().evaluate(config)
    assert result.status == ComplianceStatus.NEEDS_REVIEW
    assert "SecretHash" not in str(result.evidence)