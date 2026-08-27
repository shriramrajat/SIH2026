"""Tests for SSH-002: SSH Authentication Retries Must Be Limited."""

from __future__ import annotations

from src.compliance.model import ComplianceStatus
from src.compliance.rules.ssh_auth_retries import SshAuthRetriesRule
from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig
from src.parsers.cisco import parse_cisco
from src.parsers.juniper import parse_juniper


RULE = SshAuthRetriesRule()


def test_cisco_three_retries_passes() -> None:
    result = RULE.evaluate(parse_cisco("hostname R1\nip ssh authentication-retries 3\n"))
    assert result.status == ComplianceStatus.PASS
    assert result.remediations == []
    assert result.evidence[0].raw_lines == ("ip ssh authentication-retries 3",)


def test_cisco_below_threshold_passes() -> None:
    result = RULE.evaluate(parse_cisco("ip ssh authentication-retries 1\n"))
    assert result.status == ComplianceStatus.PASS


def test_cisco_excessive_retries_fails_with_one_remediation() -> None:
    result = RULE.evaluate(parse_cisco("ip ssh authentication-retries 4\n"))
    assert result.status == ComplianceStatus.FAIL
    assert len(result.remediations) == 1
    assert result.remediations[0].vendor == "cisco"


def test_cisco_missing_directive_fails() -> None:
    result = RULE.evaluate(parse_cisco("hostname R1\n"))
    assert result.status == ComplianceStatus.FAIL
    assert result.evidence[0].raw_lines == ()


def test_cisco_malformed_value_needs_review() -> None:
    config = NormalizedConfig(
        vendor="cisco",
        hostname="R1",
        global_items=[ConfigItem("ip", "ssh authentication-retries three", "ip ssh authentication-retries three")],
    )
    result = RULE.evaluate(config)
    assert result.status == ComplianceStatus.NEEDS_REVIEW
    assert "malformed" in result.evidence[0].note
    assert result.remediations == []


def test_cisco_unrelated_ip_directives_are_ignored() -> None:
    result = RULE.evaluate(parse_cisco("ip domain-name lab.local\nip ssh time-out 60\nip ssh authentication-retries 3\n"))
    assert result.status == ComplianceStatus.PASS


def test_cisco_duplicate_directives_use_worst_case() -> None:
    result = RULE.evaluate(parse_cisco("ip ssh authentication-retries 3\nip ssh authentication-retries 4\n"))
    assert result.status == ComplianceStatus.FAIL
    assert len(result.evidence) == 2


def test_juniper_three_retries_passes() -> None:
    result = RULE.evaluate(parse_juniper("system {\n services {\n  ssh {\n   retry-options {\n    tries-before-disconnect 3;\n   }\n  }\n }\n}\n"))
    assert result.status == ComplianceStatus.PASS
    assert result.remediations == []
    assert result.evidence[0].section_name == "system"


def test_juniper_excessive_retries_fails_with_one_remediation() -> None:
    result = RULE.evaluate(parse_juniper("system {\n services {\n  ssh {\n   retry-options {\n    tries-before-disconnect 4;\n   }\n  }\n }\n}\n"))
    assert result.status == ComplianceStatus.FAIL
    assert len(result.remediations) == 1
    assert result.remediations[0].vendor == "juniper"


def test_juniper_ignores_unrelated_tries_before_disconnect() -> None:
    # Telnet tries-before-disconnect is 10, but SSH is missing.
    # The rule must NOT treat the telnet setting as SSH configuration.
    config = "system {\n services {\n  telnet {\n   retry-options {\n    tries-before-disconnect 10;\n   }\n  }\n }\n}\n"
    result = RULE.evaluate(parse_juniper(config))
    assert result.status == ComplianceStatus.FAIL
    assert result.evidence[0].raw_lines == ()


def test_juniper_missing_configuration_fails() -> None:
    result = RULE.evaluate(parse_juniper("system {\n host-name J1;\n}\n"))
    assert result.status == ComplianceStatus.FAIL
    assert result.evidence[0].raw_lines == ()


def test_juniper_malformed_value_needs_review() -> None:
    config = NormalizedConfig(
        vendor="juniper",
        hostname="J1",
        sections=[ConfigSection("system", [ConfigItem("tries-before-disconnect", "many", "tries-before-disconnect many;", path=("services", "ssh", "retry-options"))])],
    )
    result = RULE.evaluate(config)
    assert result.status == ComplianceStatus.NEEDS_REVIEW
    assert result.evidence[0].raw_lines
    assert result.remediations == []


def test_juniper_duplicate_directives_use_worst_case() -> None:
    config = NormalizedConfig(
        vendor="juniper",
        hostname="J1",
        sections=[ConfigSection("system", [
            ConfigItem("tries-before-disconnect", "3", "tries-before-disconnect 3;", path=("services", "ssh", "retry-options")),
            ConfigItem("tries-before-disconnect", "4", "tries-before-disconnect 4;", path=("services", "ssh", "retry-options")),
        ])],
    )
    result = RULE.evaluate(config)
    assert result.status == ComplianceStatus.FAIL


def test_missing_system_section_fails() -> None:
    result = RULE.evaluate(parse_juniper("interfaces { ge-0/0/0 { disable; } }\n"))
    assert result.status == ComplianceStatus.FAIL


def test_unsupported_vendor_is_not_applicable() -> None:
    config = NormalizedConfig(vendor="arista", hostname="A1")
    result = RULE.evaluate(config)
    assert result.status == ComplianceStatus.NOT_APPLICABLE
    assert result.remediations == []
