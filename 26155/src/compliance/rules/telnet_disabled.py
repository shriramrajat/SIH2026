"""
compliance.rules.telnet_disabled
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TLN-001: Telnet management must be disabled.

Control semantics (vendor-neutral)
-----------------------------------
Telnet transmits credentials and session data in plaintext.  No
management-plane access to network devices should be permitted over
Telnet.  This control verifies that Telnet is not an allowed transport
for any virtual terminal (VTY) line or system service.

Vendor-specific extraction
---------------------------
The *decision logic* is identical: determine whether Telnet access is
permitted and return FAIL if it is, PASS if it is provably absent.

What differs is *where* the signal lives in NormalizedConfig:

Cisco IOS / IOS-XE
    VTY transport is controlled by the ``transport input`` directive
    inside one or more ``line vty <range>`` sections.

    The Cisco parser stores ``transport input ssh`` as a section item
    with:
        section.name  = "line vty 0 4"   (or any vty range)
        item.key      = "transport"
        item.value    = "input ssh"

    IMPORTANT:  ``transport output`` shares the same key ("transport").
    We filter on ``item.value.lower().startswith("input")`` to avoid
    classifying ``transport output none`` as a transport-input directive.

    A device may have multiple VTY ranges (e.g. "line vty 0 4" and
    "line vty 5 15"), each potentially configured differently.  ALL
    ranges must be evaluated.  A single non-compliant range makes the
    entire device non-compliant.

    Known transport-input values and their result
    ----------------------------------------------
    "input ssh"            PASS  (SSH-only access; Telnet excluded)
    "input none"           PASS  (no interactive access at all)
    contains "telnet"      FAIL  (Telnet explicitly permitted)
    "input all"            FAIL  (all transports including Telnet)
    absent                 NEEDS_REVIEW (IOS default varies by platform)
    other                  NEEDS_REVIEW (unrecognised value)

    Global signal: ``no service telnet`` (key="no", value="service telnet")
    is NOT used as the primary signal for this control.  VTY transport
    configuration is the definitive access-control point on IOS.

Juniper JunOS
    Services enabled on a JunOS device are listed as flag directives
    inside ``system > services``.  The JunOS parser flattens this into
    the top-level ``system`` section.

    A ``telnet;`` directive becomes:
        section.name  = "system"
        item.key      = "telnet"
        item.value    = None   (flag — no value)

    Presence  → Telnet is enabled → FAIL
    Absence   → Telnet is not enabled → PASS
    (No system section) → cannot confirm intended state → FAIL

Multi-section Cisco evaluation
-------------------------------
The rule collects a per-section verdict for every VTY range, then
combines them:

    ANY section FAIL            → overall FAIL
    No FAIL, ANY NEEDS_REVIEW   → overall NEEDS_REVIEW
    ALL sections PASS           → PASS

Evidence is produced per VTY section so the caller can see exactly
which ranges are compliant or not.
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


# ---------------------------------------------------------------------------
# Static control metadata
# ---------------------------------------------------------------------------

_CONTROL = SecurityControl(
    control_id="TLN-001",
    control_name="Telnet Must Be Disabled",
    description=(
        "Telnet transmits all data, including credentials, in plaintext "
        "and provides no protection against eavesdropping or session "
        "hijacking.  No network device should permit Telnet for management "
        "access.  SSH must be the exclusive interactive management protocol."
    ),
    severity=Severity.CRITICAL,
    framework_refs=("CIS-IOS-L2-1.3.1", "NIST-AC-17(2)", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)

# ---------------------------------------------------------------------------
# Vendor-specific remediation (returned only for the evaluated vendor)
# ---------------------------------------------------------------------------

_CISCO_REMEDIATION = Remediation(
    vendor="cisco",
    guidance=(
        "Remove 'telnet' from the 'transport input' directive on all VTY lines. "
        "Configure each VTY range to allow SSH only: "
        "'transport input ssh'. "
        "Verify with: show line vty"
    ),
    config_hint=(
        "line vty 0 4\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " transport input ssh"
    ),
)

_JUNIPER_REMEDIATION = Remediation(
    vendor="juniper",
    guidance=(
        "Remove the 'telnet' service from system services. "
        "Ensure only 'ssh' (and optionally 'netconf') are present under "
        "'system > services'. "
        "Verify with: show system services"
    ),
    config_hint="delete system services telnet",
)


# ---------------------------------------------------------------------------
# Internal per-section classification helpers
# ---------------------------------------------------------------------------

# Sentinel values used to track per-VTY-section verdict
_SEC_PASS = "pass"
_SEC_FAIL = "fail"
_SEC_NEEDS_REVIEW = "needs_review"


def _classify_transport_item(item: ConfigItem) -> str:
    """Classify a single transport-input ConfigItem.

    Returns one of the _SEC_* sentinel strings.
    """
    value = item.value.lower().strip()

    if value in ("input ssh", "input none"):
        return _SEC_PASS

    if "telnet" in value:
        return _SEC_FAIL

    if value == "input all":
        return _SEC_FAIL

    return _SEC_NEEDS_REVIEW


def _evaluate_vty_section(
    section: ConfigSection,
    control_id: str,
) -> tuple[str, Evidence]:
    """Evaluate a single VTY section and return (verdict, evidence)."""
    # Find ALL transport items, then filter to 'input' ones only.
    # This correctly excludes 'transport output' and 'transport preferred'.
    transport_items = [
        i for i in section.items
        if i.key.lower() == "transport"
        and i.value is not None
        and i.value.lower().startswith("input")
    ]

    if not transport_items:
        # No transport input directive in this VTY section.
        return (
            _SEC_NEEDS_REVIEW,
            Evidence(
                control_id=control_id,
                section_name=section.name,
                raw_lines=(),
                observed=None,
                expected="transport input ssh",
                note=(
                    f"Section '{section.name}': no 'transport input' directive "
                    "found. IOS default transport varies by platform version; "
                    "explicit configuration is required."
                ),
            ),
        )

    # There should be only one transport input directive per section on a
    # well-formed IOS config, but we take the first if multiple appear.
    item = transport_items[0]
    verdict = _classify_transport_item(item)

    if verdict == _SEC_PASS:
        note = (
            f"Section '{section.name}': transport input is "
            f"'{item.value}' — Telnet is excluded."
        )
        expected = "input ssh"
    elif verdict == _SEC_FAIL:
        note = (
            f"Section '{section.name}': transport input is "
            f"'{item.value}' — Telnet is explicitly permitted."
        )
        expected = "input ssh"
    else:
        note = (
            f"Section '{section.name}': transport input value "
            f"'{item.value}' is not a recognised specifier. "
            "Manual review required."
        )
        expected = "input ssh"

    return (
        verdict,
        Evidence(
            control_id=control_id,
            section_name=section.name,
            raw_lines=(item.raw_line,),
            observed=item.value,
            expected=expected,
            note=note,
        ),
    )


# ---------------------------------------------------------------------------
# Rule implementation
# ---------------------------------------------------------------------------


class TelnetDisabledRule(ComplianceRule):
    """Evaluates TLN-001: Telnet management must be disabled."""

    control = _CONTROL

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate Telnet-disabled compliance against *config*.

        Returns NOT_APPLICABLE for unsupported vendors.
        Delegates to vendor-specific extraction for Cisco and Juniper.
        """
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)

        if config.vendor == "cisco":
            return self._evaluate_cisco(config)

        if config.vendor == "juniper":
            return self._evaluate_juniper(config)

        # Vendor is listed as applicable but no handler implemented.
        return self._needs_review_result(
            config=config,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name=None,
                    raw_lines=(),
                    observed=None,
                    expected=None,
                    note=(
                        f"Vendor '{config.vendor}' is listed as applicable "
                        "but no extraction handler is implemented for TLN-001."
                    ),
                )
            ],
        )

    # ------------------------------------------------------------------
    # Cisco extraction
    # ------------------------------------------------------------------

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate telnet-disabled for Cisco using VTY transport directives.

        Examines every ConfigSection whose name starts with "line vty".
        Combines per-section verdicts: any FAIL → FAIL, else any
        NEEDS_REVIEW → NEEDS_REVIEW, else all-PASS → PASS.

        "transport output" is excluded by filtering on value.startswith("input").
        The global "no service telnet" directive is NOT used as a primary signal.
        """
        vty_sections = [
            sec for sec in config.sections
            if sec.name.lower().startswith("line vty")
        ]

        if not vty_sections:
            return self._needs_review_result(
                config=config,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="line vty <range> with transport input ssh",
                        note=(
                            "No 'line vty' sections found in the configuration. "
                            "Cannot determine VTY transport policy."
                        ),
                    )
                ],
            )

        # Evaluate every VTY section.
        per_section: list[tuple[str, Evidence]] = [
            _evaluate_vty_section(sec, _CONTROL.control_id)
            for sec in vty_sections
        ]

        verdicts = [v for v, _ in per_section]
        all_evidence = [e for _, e in per_section]

        if _SEC_FAIL in verdicts:
            return self._result_multi(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=all_evidence,
                remediation=_CISCO_REMEDIATION,
            )

        if _SEC_NEEDS_REVIEW in verdicts:
            return self._needs_review_result(
                config=config,
                evidence=all_evidence,
            )

        # All sections passed.
        return self._result_multi(
            config=config,
            status=ComplianceStatus.PASS,
            evidence=all_evidence,
            remediation=None,
        )

    # ------------------------------------------------------------------
    # Juniper extraction
    # ------------------------------------------------------------------

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate telnet-disabled for Juniper using system section items.

        The JunOS parser flattens system > services into system.items.
        'telnet;' becomes ConfigItem(key='telnet', value=None).
        Its presence means Telnet is enabled (FAIL).
        Its absence means Telnet is not enabled (PASS).
        """
        system = config.get_section("system")

        if system is None:
            return self._result_multi(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="system { services { /* no telnet; */ } }",
                        note=(
                            "No 'system' section found. Cannot confirm that "
                            "Telnet is absent from system services."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        telnet_item: ConfigItem | None = next(
            (i for i in system.items if i.key.lower() == "telnet"),
            None,
        )

        if telnet_item is not None:
            return self._result_multi(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(telnet_item.raw_line,),
                        observed="telnet",
                        expected="telnet service absent",
                        note=(
                            "The 'telnet' service flag is present in "
                            f"system services ('{telnet_item.raw_line.strip()}'). "
                            "Telnet is explicitly enabled."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        # Telnet flag absent — service is not enabled.
        return self._result_multi(
            config=config,
            status=ComplianceStatus.PASS,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name="system",
                    raw_lines=(),
                    observed=None,
                    expected="telnet service absent",
                    note=(
                        "No 'telnet' flag found in system services. "
                        "Telnet is not enabled."
                    ),
                )
            ],
            remediation=None,
        )

    # ------------------------------------------------------------------
    # Private result builders
    # ------------------------------------------------------------------

    def _result_multi(
        self,
        config: NormalizedConfig,
        status: ComplianceStatus,
        evidence: list[Evidence],
        remediation: Remediation | None,
    ) -> ComplianceResult:
        """Build a ComplianceResult with multiple evidence records."""
        return ComplianceResult(
            control_id=_CONTROL.control_id,
            control_name=_CONTROL.control_name,
            description=_CONTROL.description,
            severity=_CONTROL.severity,
            status=status,
            vendor=config.vendor,
            hostname=config.hostname,
            evidence=evidence,
            remediations=[remediation] if remediation is not None else [],
            framework_refs=list(_CONTROL.framework_refs),
        )

    def _needs_review_result(
        self,
        config: NormalizedConfig,
        evidence: list[Evidence],
    ) -> ComplianceResult:
        """Build a NEEDS_REVIEW ComplianceResult with pre-built evidence."""
        return ComplianceResult(
            control_id=_CONTROL.control_id,
            control_name=_CONTROL.control_name,
            description=_CONTROL.description,
            severity=_CONTROL.severity,
            status=ComplianceStatus.NEEDS_REVIEW,
            vendor=config.vendor,
            hostname=config.hostname,
            evidence=evidence,
            remediations=[],
            framework_refs=list(_CONTROL.framework_refs),
        )
