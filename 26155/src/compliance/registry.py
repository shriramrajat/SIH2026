"""
compliance.registry
~~~~~~~~~~~~~~~~~~~~

Lightweight rule registry for the compliance engine.

Usage
-----
The registry provides a single, pre-instantiated list of all active compliance
rules.  Import it wherever the full set of rules is needed:

    from src.compliance.registry import RULE_REGISTRY
    from src.compliance.engine import audit

    results = audit(config, RULE_REGISTRY)

Adding a new rule
-----------------
1. Implement the rule as a :class:`~compliance.rules.base.ComplianceRule`
   subclass in ``compliance/rules/<rule_module>.py``.
2. Add one instance of the class to the ``RULE_REGISTRY`` list below.
3. Add tests in ``tests/unit/test_<rule_module>.py``.

That is all that is required.  The engine, registry, and existing tests
require no other changes.

Rule ordering
-------------
Rules are evaluated in the order they appear in RULE_REGISTRY.  The order is
deterministic and stable across repeated calls.  Results are returned in the
same order.
"""

from __future__ import annotations

from src.compliance.rules.aaa import AaaRule
from src.compliance.rules.base import ComplianceRule
from src.compliance.rules.exec_timeout import ExecTimeoutRule
from src.compliance.rules.pwd_encryption import PwdEncryptionRule
from src.compliance.rules.ssh_version import SshVersionRule
from src.compliance.rules.telnet_disabled import TelnetDisabledRule

#: Ordered list of all active compliance rule instances.
#:
#: Rules are evaluated against a :class:`~normalization.model.NormalizedConfig`
#: by :func:`~compliance.engine.audit`.  Each rule produces exactly one
#: :class:`~compliance.model.ComplianceResult`.
RULE_REGISTRY: list[ComplianceRule] = [
    SshVersionRule(),
    TelnetDisabledRule(),
    ExecTimeoutRule(),
    PwdEncryptionRule(),
    AaaRule(),
]
