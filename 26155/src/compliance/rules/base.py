"""
compliance.rules.base
~~~~~~~~~~~~~~~~~~~~~

Abstract base for all compliance rules and the static SecurityControl
metadata descriptor.

Design intent
-------------
- ``SecurityControl`` is a frozen dataclass holding *only* static metadata.
  It has no evaluation logic.  This allows a control catalogue to be
  generated without instantiating rule evaluators.

- ``ComplianceRule`` is the abstract evaluator contract.  One subclass
  per control, each in its own module under ``compliance/rules/``.

- Rules may contain vendor-specific *extraction* paths through
  ``NormalizedConfig``, but the control semantics (what constitutes a
  PASS or FAIL) must remain vendor-neutral.

- Rules must NOT import or reference vendor parsers directly.
- Rules must NOT use regex or string parsing on ``ConfigItem.raw_line``
  to extract values; the value is already available in ``ConfigItem.value``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Severity,
)
from src.normalization.model import NormalizedConfig


@dataclass(frozen=True)
class SecurityControl:
    """Static metadata descriptor for a security control.

    Parameters
    ----------
    control_id:
        Unique identifier (e.g. ``"SSH-001"``).
    control_name:
        Short human-readable name (e.g. ``"SSH Protocol Version"``).
    description:
        One-paragraph plain-English description of what this control checks.
    severity:
        Business-impact severity.
    framework_refs:
        Tuple of compliance framework references.
    applicable_vendors:
        ``frozenset`` of vendor strings this control applies to.
        Use ``frozenset({"*"})`` to match all vendors.
    """

    control_id: str
    control_name: str
    description: str
    severity: Severity
    framework_refs: tuple[str, ...]
    applicable_vendors: frozenset[str]

    def applies_to(self, vendor: str) -> bool:
        """Return ``True`` if this control applies to *vendor*."""
        return "*" in self.applicable_vendors or vendor in self.applicable_vendors


class ComplianceRule(abc.ABC):
    """Abstract base for all compliance rules.

    Subclasses must define a class-level ``control`` attribute and
    implement :meth:`evaluate`.

    Evaluation contract
    -------------------
    - ``evaluate()`` receives a fully-parsed :class:`NormalizedConfig`.
    - It must return a :class:`ComplianceResult` for every call.
    - The same input always produces the same output (deterministic).
    - Vendor applicability is the rule's responsibility; call
      ``self._not_applicable(config)`` as the first check.
    """

    control: SecurityControl  # must be set at class level by every subclass

    @abc.abstractmethod
    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate the control against *config* and return a result."""

    # ------------------------------------------------------------------
    # Protected helpers available to all subclasses
    # ------------------------------------------------------------------

    def _not_applicable(self, config: NormalizedConfig) -> ComplianceResult:
        """Produce a NOT_APPLICABLE result for *config*."""
        return self._build_result(
            config=config,
            status=ComplianceStatus.NOT_APPLICABLE,
            evidence=[
                Evidence(
                    control_id=self.control.control_id,
                    section_name=None,
                    raw_lines=(),
                    observed=None,
                    expected=None,
                    note=(
                        f"Control '{self.control.control_id}' does not apply "
                        f"to vendor '{config.vendor}'."
                    ),
                )
            ],
            remediation=None,
        )

    def _build_result(
        self,
        config: NormalizedConfig,
        status: ComplianceStatus,
        evidence: list[Evidence],
        remediation: Remediation | None = None,
    ) -> ComplianceResult:
        """Construct a ComplianceResult with standard metadata."""
        return ComplianceResult(
            control_id=self.control.control_id,
            control_name=self.control.control_name,
            description=self.control.description,
            severity=self.control.severity,
            status=status,
            vendor=config.vendor,
            hostname=config.hostname,
            evidence=evidence,
            remediations=[remediation] if remediation is not None else [],
            framework_refs=list(self.control.framework_refs),
        )
