"""SSH-002: SSH authentication retries must be limited."""

from __future__ import annotations

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Remediation,
    Severity,
)
from src.compliance.rules.base import ComplianceRule, SecurityControl
from src.normalization.model import ConfigItem, NormalizedConfig


MAX_AUTH_RETRIES = 3

_CONTROL = SecurityControl(
    control_id="SSH-002",
    control_name="SSH Authentication Retries Must Be Limited",
    description=(
        "SSH authentication attempts must be limited to reduce exposure to "
        "automated brute-force attacks."
    ),
    severity=Severity.MEDIUM,
    framework_refs=("CIS-IOS-L2-1.1.2", "NIST-AC-7", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)

_CISCO_REMEDIATION = Remediation(
    vendor="cisco",
    guidance=(
        "Configure SSH authentication retries to 3 or fewer attempts globally."
    ),
    config_hint="ip ssh authentication-retries 3",
)

_JUNIPER_REMEDIATION = Remediation(
    vendor="juniper",
    guidance=(
        "Configure SSH tries-before-disconnect to 3 or fewer attempts under "
        "system services ssh."
    ),
    config_hint="set system services ssh retry-options tries-before-disconnect 3",
)

_PASS = "pass"
_FAIL = "fail"
_REVIEW = "review"
_CISCO_PREFIX = "ssh authentication-retries"


def _classify(value: str) -> tuple[str, int | None]:
    """Classify a numeric retry value without accepting trailing junk."""
    text = value.strip()
    if not text or not text.isdecimal():
        return _REVIEW, None
    attempts = int(text)
    if attempts == 0:
        return _REVIEW, attempts
    if attempts <= MAX_AUTH_RETRIES:
        return _PASS, attempts
    return _FAIL, attempts


def _aggregate(verdicts: list[str]) -> ComplianceStatus:
    if _FAIL in verdicts:
        return ComplianceStatus.FAIL
    if _REVIEW in verdicts:
        return ComplianceStatus.NEEDS_REVIEW
    return ComplianceStatus.PASS


class SshAuthRetriesRule(ComplianceRule):
    """Evaluate SSH-002 for Cisco IOS/IOS-XE and Juniper JunOS."""

    control = _CONTROL

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)
        if config.vendor == "cisco":
            return self._evaluate_cisco(config)
        if config.vendor == "juniper":
            return self._evaluate_juniper(config)
        return self._not_applicable(config)

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        items = [
            item for item in config.global_items
            if item.key.lower() == "ip"
            and item.value is not None
            and item.value.lower().startswith(_CISCO_PREFIX)
        ]
        if not items:
            return self._build_result(
                config,
                ComplianceStatus.FAIL,
                [Evidence(
                    self.control.control_id, None, (), None,
                    f"ip ssh authentication-retries 1-{MAX_AUTH_RETRIES}",
                    "No SSH authentication-retries directive was found.",
                )],
                _CISCO_REMEDIATION,
            )

        evidence: list[Evidence] = []
        verdicts: list[str] = []
        for item in items:
            suffix = item.value[len(_CISCO_PREFIX):].strip()
            verdict, attempts = _classify(suffix)
            verdicts.append(verdict)
            if attempts is None:
                note = "SSH authentication-retries is malformed; manual review is required."
                observed = item.value
            elif verdict == _PASS:
                note = f"SSH authentication retries are limited to {attempts}."
                observed = str(attempts)
            elif verdict == _FAIL:
                note = f"SSH authentication retries are set to {attempts}, exceeding the limit."
                observed = str(attempts)
            else:
                note = "SSH authentication-retries is zero and cannot be classified safely."
                observed = str(attempts)
            evidence.append(Evidence(
                self.control.control_id, None, (item.raw_line,), observed,
                f"1-{MAX_AUTH_RETRIES} attempts", note,
            ))
        status = _aggregate(verdicts)
        return self._build_result(
            config, status, evidence,
            _CISCO_REMEDIATION if status == ComplianceStatus.FAIL else None,
        )

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        system = config.get_section("system")
        if system is None:
            return self._build_result(
                config,
                ComplianceStatus.FAIL,
                [Evidence(
                    self.control.control_id, None, (), None,
                    f"tries-before-disconnect 1-{MAX_AUTH_RETRIES}",
                    "No system section was found, so SSH retry policy cannot be confirmed.",
                )],
                _JUNIPER_REMEDIATION,
            )

        items = [
            item for item in system.items
            if item.key.lower() == "tries-before-disconnect"
        ]
        if not items:
            return self._build_result(
                config,
                ComplianceStatus.FAIL,
                [Evidence(
                    self.control.control_id, "system", (), None,
                    f"tries-before-disconnect 1-{MAX_AUTH_RETRIES}",
                    "No tries-before-disconnect directive was found under system services ssh.",
                )],
                _JUNIPER_REMEDIATION,
            )

        evidence: list[Evidence] = []
        verdicts: list[str] = []
        for item in items:
            if item.value is None:
                verdict, attempts = _REVIEW, None
            else:
                verdict, attempts = _classify(item.value)
            verdicts.append(verdict)
            if attempts is None:
                note = "tries-before-disconnect is malformed; manual review is required."
                observed = item.value
            elif verdict == _PASS:
                note = f"SSH authentication retries are limited to {attempts}."
                observed = str(attempts)
            elif verdict == _FAIL:
                note = f"SSH authentication retries are set to {attempts}, exceeding the limit."
                observed = str(attempts)
            else:
                note = "tries-before-disconnect is zero and cannot be classified safely."
                observed = str(attempts)
            evidence.append(Evidence(
                self.control.control_id, "system", (item.raw_line,), observed,
                f"1-{MAX_AUTH_RETRIES} attempts", note,
            ))
        status = _aggregate(verdicts)
        return self._build_result(
            config, status, evidence,
            _JUNIPER_REMEDIATION if status == ComplianceStatus.FAIL else None,
        )