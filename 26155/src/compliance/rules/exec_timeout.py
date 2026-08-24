"""
compliance.rules.exec_timeout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

EXEC-001: VTY Idle Session Timeout Must Be Configured.

Control semantics (vendor-neutral)
-----------------------------------
Idle management sessions left unattended present a high risk of unauthorized
access. This control verifies that an idle session timeout is configured
and set to 10 minutes (600 seconds) or less.

Vendor-specific extraction
---------------------------
Cisco IOS / IOS-XE
    VTY session timeout is controlled by the ``exec-timeout <minutes> <seconds>``
    directive within each ``line vty <range>`` section.

    Multiple VTY ranges must all be evaluated. If any range fails, the entire
    device fails. If any range is missing the directive or has a malformed
    value, the overall result may be NEEDS_REVIEW (unless another range fails).

Juniper JunOS
    Idle timeout is controlled by ``idle-timeout <minutes>;`` under the
    ``system > login`` hierarchy. The JunOS parser flattens this into the
    ``system`` section.
"""

from __future__ import annotations

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Remediation,
    Severity,
)
from src.compliance.rules.base import ComplianceRule, SecurityControl
from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig


_CONTROL = SecurityControl(
    control_id="EXEC-001",
    control_name="VTY Idle Session Timeout Must Be Configured",
    description=(
        "Idle management sessions left unattended present a high risk of unauthorized "
        "access. An idle session timeout must be configured and set to 10 minutes "
        "(600 seconds) or less."
    ),
    severity=Severity.HIGH,
    framework_refs=("CIS-IOS-L2-2.1.1", "NIST-AC-17(2)", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)


_CISCO_REMEDIATION = Remediation(
    vendor="cisco",
    guidance=(
        "Configure an explicit exec-timeout of 10 minutes or less on every VTY range."
    ),
    config_hint=(
        "line vty 0 4\n"
        " exec-timeout 10 0"
    ),
)


_JUNIPER_REMEDIATION = Remediation(
    vendor="juniper",
    guidance=(
        "Configure an explicit idle-timeout of 10 minutes or less under system login."
    ),
    config_hint="set system login idle-timeout 10",
)


# Internal per-section classification helpers
_SEC_PASS = "pass"
_SEC_FAIL = "fail"
_SEC_NEEDS_REVIEW = "needs_review"


def _evaluate_vty_section(
    section: ConfigSection,
    control_id: str,
) -> tuple[str, Evidence]:
    """Evaluate a single VTY section for Cisco and return (verdict, evidence)."""
    # Find exec-timeout item
    exec_item = next(
        (i for i in section.items if i.key.lower() == "exec-timeout"),
        None,
    )

    if exec_item is None:
        return (
            _SEC_NEEDS_REVIEW,
            Evidence(
                control_id=control_id,
                section_name=section.name,
                raw_lines=(),
                observed=None,
                expected="exec-timeout ≤ 10 minutes (600s)",
                note=(
                    f"Section '{section.name}': no 'exec-timeout' directive found. "
                    "Default timeout varies by platform; explicit configuration is required."
                ),
            ),
        )

    if exec_item.value is None:
        return (
            _SEC_NEEDS_REVIEW,
            Evidence(
                control_id=control_id,
                section_name=section.name,
                raw_lines=(exec_item.raw_line,),
                observed=None,
                expected="exec-timeout ≤ 10 minutes (600s)",
                note=(
                    f"Section '{section.name}': 'exec-timeout' directive found but "
                    "has no value. Manual review required."
                ),
            ),
        )

    parts = exec_item.value.split()
    if len(parts) != 2:
        return (
            _SEC_NEEDS_REVIEW,
            Evidence(
                control_id=control_id,
                section_name=section.name,
                raw_lines=(exec_item.raw_line,),
                observed=exec_item.value,
                expected="exec-timeout ≤ 10 minutes (600s)",
                note=(
                    f"Section '{section.name}': 'exec-timeout' value '{exec_item.value}' "
                    "does not have exactly two parts. Manual review required."
                ),
            ),
        )

    try:
        minutes = int(parts[0])
        seconds = int(parts[1])
    except ValueError:
        return (
            _SEC_NEEDS_REVIEW,
            Evidence(
                control_id=control_id,
                section_name=section.name,
                raw_lines=(exec_item.raw_line,),
                observed=exec_item.value,
                expected="exec-timeout ≤ 10 minutes (600s)",
                note=(
                    f"Section '{section.name}': 'exec-timeout' value '{exec_item.value}' "
                    "could not be parsed as two integers. Manual review required."
                ),
            ),
        )

    total_seconds = minutes * 60 + seconds

    if total_seconds == 0:
        verdict = _SEC_FAIL
        note = f"Section '{section.name}': exec-timeout is disabled (0 0)."
    elif 0 < total_seconds <= 600:
        verdict = _SEC_PASS
        note = f"Section '{section.name}': exec-timeout is {total_seconds}s (≤ 600s threshold)."
    else:
        verdict = _SEC_FAIL
        note = f"Section '{section.name}': exec-timeout is {total_seconds}s (exceeds 600s threshold)."

    return (
        verdict,
        Evidence(
            control_id=control_id,
            section_name=section.name,
            raw_lines=(exec_item.raw_line,),
            observed=exec_item.value,
            expected="exec-timeout ≤ 10 minutes (600s)",
            note=note,
        ),
    )


class ExecTimeoutRule(ComplianceRule):
    """Evaluates EXEC-001: VTY Idle Session Timeout Must Be Configured."""

    control = _CONTROL

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate VTY timeout compliance against *config*."""
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)

        if config.vendor == "cisco":
            return self._evaluate_cisco(config)

        if config.vendor == "juniper":
            return self._evaluate_juniper(config)

        return self._build_result(
            config=config,
            status=ComplianceStatus.NEEDS_REVIEW,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name=None,
                    raw_lines=(),
                    observed=None,
                    expected=None,
                    note=(
                        f"Vendor '{config.vendor}' is listed as applicable "
                        "but no extraction handler is implemented for EXEC-001."
                    ),
                )
            ],
        )

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        vty_sections = [
            sec for sec in config.sections
            if sec.name.lower().startswith("line vty")
        ]

        if not vty_sections:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="line vty <range> with exec-timeout configured",
                        note=(
                            "No 'line vty' sections found in the configuration. "
                            "Cannot determine VTY session timeout policy."
                        ),
                    )
                ],
            )

        per_section: list[tuple[str, Evidence]] = [
            _evaluate_vty_section(sec, _CONTROL.control_id)
            for sec in vty_sections
        ]

        verdicts = [v for v, _ in per_section]
        all_evidence = [e for _, e in per_section]

        if _SEC_FAIL in verdicts:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=all_evidence,
                remediation=_CISCO_REMEDIATION,
            )

        if _SEC_NEEDS_REVIEW in verdicts:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=all_evidence,
            )

        return self._build_result(
            config=config,
            status=ComplianceStatus.PASS,
            evidence=all_evidence,
            remediation=None,
        )

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        system = config.get_section("system")

        if system is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="idle-timeout ≤ 10",
                        note=(
                            "No 'system' section found. Cannot determine "
                            "idle-timeout policy."
                        ),
                    )
                ],
            )

        timeout_item = next(
            (i for i in system.items if i.key.lower() == "idle-timeout"),
            None,
        )

        if timeout_item is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(),
                        observed=None,
                        expected="idle-timeout ≤ 10",
                        note=(
                            "No 'idle-timeout' directive found in system section. "
                            "Explicit configuration is required."
                        ),
                    )
                ],
            )

        if timeout_item.value is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(timeout_item.raw_line,),
                        observed=None,
                        expected="idle-timeout ≤ 10",
                        note=(
                            "'idle-timeout' directive found but has no value. "
                            "Manual review required."
                        ),
                    )
                ],
            )

        try:
            minutes = int(timeout_item.value)
        except ValueError:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(timeout_item.raw_line,),
                        observed=timeout_item.value,
                        expected="idle-timeout ≤ 10",
                        note=(
                            f"'idle-timeout' value '{timeout_item.value}' could "
                            "not be parsed as an integer. Manual review required."
                        ),
                    )
                ],
            )

        if minutes == 0:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(timeout_item.raw_line,),
                        observed=timeout_item.value,
                        expected="idle-timeout ≤ 10",
                        note="idle-timeout is disabled (0).",
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )
        elif 0 < minutes <= 10:
            return self._build_result(
                config=config,
                status=ComplianceStatus.PASS,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(timeout_item.raw_line,),
                        observed=timeout_item.value,
                        expected="idle-timeout ≤ 10",
                        note=f"idle-timeout is {minutes}m (≤ 10m threshold).",
                    )
                ],
                remediation=None,
            )
        else:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(timeout_item.raw_line,),
                        observed=timeout_item.value,
                        expected="idle-timeout ≤ 10",
                        note=f"idle-timeout is {minutes}m (exceeds 10m threshold).",
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )
