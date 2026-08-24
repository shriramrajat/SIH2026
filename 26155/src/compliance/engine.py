"""
compliance.engine
~~~~~~~~~~~~~~~~~

Minimal audit runner.

The engine has no awareness of individual rules or vendors.
It delegates all evaluation to :class:`~compliance.rules.base.ComplianceRule`
subclasses and assembles their results in order.
"""

from __future__ import annotations

from src.compliance.model import ComplianceResult
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
    """
    return [rule.evaluate(config) for rule in rules]
