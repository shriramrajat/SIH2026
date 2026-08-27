"""
compliance.engine
~~~~~~~~~~~~~~~~~

Minimal audit runner.

The engine has no awareness of individual rules or vendors.
It delegates all evaluation to :class:`~compliance.rules.base.ComplianceRule`
subclasses and assembles their results in order.

Error isolation
---------------
Each rule is evaluated in isolation.  If a rule raises an unhandled exception,
the engine captures it and returns a ``NEEDS_REVIEW`` result for that rule
rather than propagating the exception.  This ensures that one broken rule
cannot abort evaluation of the remaining rules.

The exception message is preserved in the evidence ``note`` field so the
problem remains visible and debuggable without crashing the caller.
"""

from __future__ import annotations

import traceback

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Severity,
)
from src.compliance.rules.base import ComplianceRule
from src.normalization.model import NormalizedConfig


def audit(
    config: NormalizedConfig,
    rules: list[ComplianceRule],
) -> list[ComplianceResult]:
    """Evaluate *config* against every rule in *rules*.

    Parameters
    ----------
    config:
        The fully-parsed, vendor-neutral configuration to audit.
    rules:
        Ordered list of :class:`ComplianceRule` instances to evaluate.

    Returns
    -------
    list[ComplianceResult]
        One result per rule, in the same order as *rules*.
        Results are never omitted — a crashing rule produces a
        ``NEEDS_REVIEW`` result with the exception detail in the evidence.
    """
    results: list[ComplianceResult] = []
    for rule in rules:
        try:
            results.append(rule.evaluate(config))
        except Exception:  # noqa: BLE001
            # Capture the traceback text for debuggability.
            tb_text = traceback.format_exc()
            results.append(
                ComplianceResult(
                    control_id=_safe_control_id(rule),
                    control_name=_safe_control_name(rule),
                    description=(
                        "Rule evaluation failed with an unhandled exception. "
                        "This is a bug in the rule implementation, not in the "
                        "configuration under audit."
                    ),
                    severity=Severity.INFO,
                    status=ComplianceStatus.NEEDS_REVIEW,
                    vendor=config.vendor,
                    hostname=config.hostname,
                    evidence=[
                        Evidence(
                            control_id=_safe_control_id(rule),
                            section_name=None,
                            raw_lines=(),
                            observed=None,
                            expected=None,
                            note=(
                                f"Rule '{_safe_control_id(rule)}' raised an "
                                f"unhandled exception during evaluation:\n{tb_text}"
                            ),
                        )
                    ],
                    remediations=[],
                    framework_refs=[],
                )
            )
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_control_id(rule: ComplianceRule) -> str:
    """Return the rule's control_id without raising if the attribute is missing."""
    try:
        return rule.control.control_id
    except AttributeError:
        return "UNKNOWN"


def _safe_control_name(rule: ComplianceRule) -> str:
    """Return the rule's control_name without raising if the attribute is missing."""
    try:
        return rule.control.control_name
    except AttributeError:
        return "Unknown Rule"
