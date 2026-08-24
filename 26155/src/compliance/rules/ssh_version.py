"""
compliance.rules.ssh_version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SSH-001: SSH Protocol Version Must Be 2

Control semantics (vendor-neutral)
-----------------------------------
SSH must be configured to use protocol version 2 exclusively.
Protocol version 1 is cryptographically broken and must not be permitted.

Vendor-specific extraction
---------------------------
The *decision logic* is identical across vendors: find the SSH version
directive and check whether it specifies version 2.

What differs is *where* the directive lives in NormalizedConfig:

Cisco IOS / IOS-XE
    The directive ``ip ssh version 2`` is a global item.
    The Cisco parser tokenises on the first space, so:
        key   = "ip"
        value = "ssh version 2"

    IMPORTANT: Multiple ``ip ...`` directives share the same key.
    ``get_global("ip")`` returns only the FIRST such item, which may
    be ``ip domain-name`` or any other ``ip ...`` directive.

    Correct extraction: iterate ALL global_items, filter on
        key == "ip"  AND  value starts with "ssh version"
    This is O(n) over global_items but correct regardless of ordering.

Juniper JunOS
    The directive ``protocol-version v2;`` is nested inside
    ``system > services > ssh``.  The JunOS parser flattens nested
    blocks into the enclosing top-level section, so the item appears
    in the ``system`` section's items list with:
        key   = "protocol-version"
        value = "v2"

Known values and their status
------------------------------
    Cisco        Juniper        Status
    ------       -------        ------
    ssh version 2  v2           PASS
    ssh version 1  v1           FAIL
    absent         absent       FAIL
    other          other        NEEDS_REVIEW
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
from src.normalization.model import ConfigItem, NormalizedConfig


# ---------------------------------------------------------------------------
# Static control metadata
# ---------------------------------------------------------------------------

_CONTROL = SecurityControl(
    control_id="SSH-001",
    control_name="SSH Protocol Version",
    description=(
        "SSH must be configured to use protocol version 2 exclusively. "
        "SSHv1 contains known cryptographic weaknesses (MITM via session "
        "injection, weak key exchange) and must not be permitted on any "
        "managed network device."
    ),
    severity=Severity.HIGH,
    framework_refs=("CIS-IOS-L2-1.1.1", "NIST-AC-17(2)", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)

# ---------------------------------------------------------------------------
# Vendor-specific remediation (returned only for the matching vendor)
# ---------------------------------------------------------------------------

_CISCO_REMEDIATION = Remediation(
    vendor="cisco",
    guidance=(
        "Add 'ip ssh version 2' to the global configuration. "
        "Ensure no 'ip ssh version 1' directive is present. "
        "Verify with: show ip ssh"
    ),
    config_hint="ip ssh version 2",
)

_JUNIPER_REMEDIATION = Remediation(
    vendor="juniper",
    guidance=(
        "Under system > services > ssh, set 'protocol-version v2;'. "
        "Remove any 'protocol-version v1;' directive. "
        "Verify with: show system services ssh"
    ),
    config_hint="set system services ssh protocol-version v2",
)


# ---------------------------------------------------------------------------
# Rule implementation
# ---------------------------------------------------------------------------


class SshVersionRule(ComplianceRule):
    """Evaluates SSH-001: SSH Protocol Version Must Be 2."""

    control = _CONTROL

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate SSH protocol version compliance against *config*.

        Returns NOT_APPLICABLE for unsupported vendors.
        Delegates to vendor-specific extraction for Cisco and Juniper.
        """
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)

        if config.vendor == "cisco":
            return self._evaluate_cisco(config)

        if config.vendor == "juniper":
            return self._evaluate_juniper(config)

        # Recognised as applicable but no handler implemented — be safe.
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
                        f"Vendor '{config.vendor}' is listed as applicable but no "
                        "extraction handler has been implemented for SSH-001."
                    ),
                )
            ],
        )

    # ------------------------------------------------------------------
    # Cisco extraction
    # ------------------------------------------------------------------

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        """Extract and evaluate SSH version from a Cisco NormalizedConfig.

        The Cisco parser stores ``ip ssh version 2`` as a global item with
        key="ip" and value="ssh version 2".  Because multiple ``ip ...``
        directives share the same key, ``get_global("ip")`` is unreliable —
        it returns the *first* such item which may be ``ip domain-name`` or
        any other directive.

        Strategy: scan all global_items for an item where:
            key  == "ip"
            value starts with "ssh version"
        This is correct regardless of the ordering of ip-prefixed directives.
        """
        ssh_item: ConfigItem | None = next(
            (
                i
                for i in config.global_items
                if i.key.lower() == "ip"
                and i.value is not None
                and i.value.lower().startswith("ssh version")
            ),
            None,
        )

        if ssh_item is None:
            # No SSH version directive found at all.
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="ip ssh version 2",
                        note=(
                            "No 'ip ssh version' directive found in global "
                            "configuration. SSH version is not explicitly set."
                        ),
                    )
                ],
                remediation=_CISCO_REMEDIATION,
            )

        # A version directive was found — inspect the value.
        value = ssh_item.value.lower()  # e.g. "ssh version 2"

        if value == "ssh version 2":
            return self._build_result(
                config=config,
                status=ComplianceStatus.PASS,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(ssh_item.raw_line,),
                        observed=ssh_item.value,
                        expected="ssh version 2",
                        note="SSH version 2 is explicitly configured globally.",
                    )
                ],
                remediation=None,
            )

        if value == "ssh version 1":
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(ssh_item.raw_line,),
                        observed=ssh_item.value,
                        expected="ssh version 2",
                        note=(
                            f"SSH is explicitly configured for version 1 "
                            f"('{ssh_item.raw_line.strip()}'). "
                            "SSHv1 is cryptographically broken."
                        ),
                    )
                ],
                remediation=_CISCO_REMEDIATION,
            )

        # Unknown value — cannot safely classify.
        return self._build_result(
            config=config,
            status=ComplianceStatus.NEEDS_REVIEW,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name=None,
                    raw_lines=(ssh_item.raw_line,),
                    observed=ssh_item.value,
                    expected=None,
                    note=(
                        f"SSH version directive found ('{ssh_item.raw_line.strip()}') "
                        f"but value '{ssh_item.value}' is not a recognised version "
                        "specifier. Manual review required."
                    ),
                )
            ],
        )

    # ------------------------------------------------------------------
    # Juniper extraction
    # ------------------------------------------------------------------

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        """Extract and evaluate SSH version from a Juniper NormalizedConfig.

        The JunOS parser flattens nested blocks (system > services > ssh)
        into the top-level 'system' section.  The 'protocol-version' item
        is therefore found in system.items.
        """
        system = config.get_section("system")

        if system is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="system { services { ssh { protocol-version v2; } } }",
                        note=(
                            "No 'system' section found in the configuration. "
                            "Cannot determine SSH version."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        pv_item: ConfigItem | None = next(
            (
                i
                for i in system.items
                if i.key.lower() == "protocol-version"
            ),
            None,
        )

        if pv_item is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(),
                        observed=None,
                        expected="protocol-version v2",
                        note=(
                            "'system' section exists but no 'protocol-version' "
                            "directive was found. SSH version is not explicitly set."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        value = (pv_item.value or "").lower().strip()

        if value == "v2":
            return self._build_result(
                config=config,
                status=ComplianceStatus.PASS,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(pv_item.raw_line,),
                        observed=pv_item.value,
                        expected="v2",
                        note="SSH protocol-version is set to 'v2' under system.",
                    )
                ],
                remediation=None,
            )

        if value == "v1":
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(pv_item.raw_line,),
                        observed=pv_item.value,
                        expected="v2",
                        note=(
                            f"SSH protocol-version is set to 'v1' "
                            f"('{pv_item.raw_line.strip()}'). "
                            "SSHv1 is cryptographically broken."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        # Unknown value.
        return self._build_result(
            config=config,
            status=ComplianceStatus.NEEDS_REVIEW,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name="system",
                    raw_lines=(pv_item.raw_line,),
                    observed=pv_item.value,
                    expected=None,
                    note=(
                        f"'protocol-version' directive found "
                        f"('{pv_item.raw_line.strip()}') but value "
                        f"'{pv_item.value}' is not a recognised version specifier. "
                        "Manual review required."
                    ),
                )
            ],
        )


