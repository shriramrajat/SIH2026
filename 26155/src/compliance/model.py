"""
compliance.model
~~~~~~~~~~~~~~~~

Vendor-neutral data model for compliance evaluation results.

Design intent
-------------
These dataclasses carry the *output* of the compliance engine.
They have no evaluation logic; that lives in ComplianceRule subclasses.

Keep this module free of parser imports.  The only allowed import from
the project is ``Severity`` (an enum that belongs naturally here).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Business-impact severity of a security control.

    Severity communicates risk priority to operators.  It does NOT
    drive the compliance decision (PASS/FAIL is determined by the rule).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(enum.Enum):
    """Result state produced by a :class:`~compliance.rules.base.ComplianceRule`.

    PASS
        The configuration satisfies the control requirement.
    FAIL
        The configuration violates the control requirement.
    NOT_APPLICABLE
        The control does not apply to this vendor or device type.
        A NOT_APPLICABLE result is not a finding and should not be
        treated as a compliance failure.
    NEEDS_REVIEW
        The parser found the relevant section but the extracted value is
        ambiguous, unrecognised, or outside the set of known states.
        A human reviewer must inspect the configuration manually.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True)
class Evidence:
    """Immutable record linking a compliance decision back to the configuration.

    Parameters
    ----------
    control_id:
        The control this evidence belongs to (e.g. ``"SSH-001"``).
    section_name:
        The :class:`~normalization.model.ConfigSection` name from which
        the item was drawn, or ``None`` for global items.
    raw_lines:
        One or more ``ConfigItem.raw_line`` strings from the parsed
        configuration.  An empty tuple signals *absence evidence* — the
        relevant directive was not found.
    observed:
        The value the rule actually found, as a human-readable string.
        ``None`` when the directive was absent.
    expected:
        The value or condition the rule required, as a human-readable string.
    note:
        Mandatory free-form explanation.  A reviewer reading only this
        field must understand *why* the rule reached its conclusion.
    """

    control_id: str
    section_name: str | None
    raw_lines: tuple[str, ...]
    observed: str | None
    expected: str | None
    note: str


@dataclass(frozen=True)
class Remediation:
    """Read-only corrective guidance for a non-compliant control.

    Parameters
    ----------
    vendor:
        The vendor this remediation applies to (e.g. ``"cisco"``).
        Use ``"any"`` when the same guidance applies across all vendors.
    guidance:
        Specific, actionable plain-English instructions.  No jargon.
    config_hint:
        An example configuration snippet illustrating the required change.
        **Must never be applied automatically.**  It is advisory only.
    """

    vendor: str
    guidance: str
    config_hint: str | None = None


@dataclass
class ComplianceResult:
    """Output produced by a single :class:`~compliance.rules.base.ComplianceRule`.

    Parameters
    ----------
    control_id:
        Unique identifier for the security control (e.g. ``"SSH-001"``).
    control_name:
        Human-readable control name (e.g. ``"SSH Protocol Version"``).
    description:
        One-paragraph plain-English description of what the control checks.
    severity:
        Business-impact severity of this control.
    status:
        Compliance evaluation outcome.
    vendor:
        Vendor string from the evaluated :class:`~normalization.model.NormalizedConfig`.
    hostname:
        Device hostname from the evaluated config, or ``None`` if absent.
    evidence:
        Ordered list of evidence records.  Always populated regardless of
        status — a PASS result must show *why* it passed.
    remediations:
        Corrective guidance relevant to ``vendor``.  Empty when
        ``status == ComplianceStatus.PASS``.
    framework_refs:
        Compliance framework references (e.g. ``["CIS-IOS-L2-1.1.1"]``).
    """

    control_id: str
    control_name: str
    description: str
    severity: Severity
    status: ComplianceStatus
    vendor: str
    hostname: str | None
    evidence: list[Evidence] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    framework_refs: list[str] = field(default_factory=list)
