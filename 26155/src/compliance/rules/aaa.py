"""
compliance.rules.aaa
~~~~~~~~~~~~~~~~~~~~~

AAA-001: Remote AAA Authentication Must Be Primary.

Control semantics (vendor-neutral)
------------------------------------
Centralized (remote) AAA enforces consistent access control across all
management sessions, enables real-time audit logging, supports role-based
access control, and allows immediate credential revocation.  When local
authentication is primary, none of these properties hold: compromised local
credentials are invisible to central audit systems, revocation requires
touching every device individually, and access cannot be denied in real time.

This control verifies that a remote AAA method (RADIUS or TACACS+) is the
FIRST (primary) method in the default authentication list for management
access.  A local fallback is acceptable but must not be primary.

Vendor-specific extraction
---------------------------

Cisco IOS / IOS-XE
    All AAA directives land in ``NormalizedConfig.global_items`` with
    ``item.key == "aaa"``.  The full semantic content is in ``item.value``.

    Key observations from probe results:
    - ``get_global("aaa")`` returns only the FIRST aaa item.  This rule
      MUST iterate ``config.global_items`` directly.
    - ``aaa new-model`` → key="aaa", value="new-model"
    - ``aaa authentication login default group radius local``
        → key="aaa", value="authentication login default group radius local"
    - All aaa lines share the same key.  Semantics are entirely in value.

    Evaluation path:
    1. Find items where key="aaa" and value="new-model" → AAA active flag.
    2. Find items where value starts with "authentication login default ".
    3. Extract the method suffix after that prefix.
    4. Classify the first method token:
       - "group <anything>"  → remote → PASS
       - "local"             → local  → FAIL
       - "none"              → open   → FAIL
       - anything else       → NEEDS_REVIEW

Juniper JunOS
    AAA ordering is expressed via ``authentication-order`` inside
    ``system {}``.  The Juniper parser captures the full bracket expression
    as the ConfigItem value:

        authentication-order [ radius password ];
        → key="authentication-order", value="[ radius password ]"

    The first token inside the brackets is the primary method.

    IMPORTANT: ``radius-server {}`` and ``tacplus-server {}`` sub-blocks are
    flattened into ``system.items`` with ambiguous keys (IP addresses, port,
    secret).  These are NOT reliable signals.  Only ``authentication-order``
    is used.

    Evaluation path:
    1. ``config.get_section("system")`` — section must exist.
    2. Find item with key="authentication-order".
    3. Strip "[ ]", split, inspect first token:
       - "radius" or "tacplus" → PASS
       - "password"            → FAIL
       - anything else         → NEEDS_REVIEW

Rules about raw_line
---------------------
Evidence uses ``ConfigItem.raw_line`` only for the ``raw_lines`` field.
The compliance decision is made exclusively from ``item.value``.
No parsing of ``item.raw_line`` is performed.

Multi-default list handling
-----------------------------
If two or more ``aaa authentication login default`` items are found the
configuration is ambiguous.  The rule returns NEEDS_REVIEW with an
explanatory note.
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
    control_id="AAA-001",
    control_name="Remote AAA Authentication Must Be Primary",
    description=(
        "Centralized (remote) AAA enforces consistent access control, enables "
        "real-time audit logging, supports role-based access control, and allows "
        "immediate credential revocation without touching individual devices. "
        "This control verifies that a remote AAA method (RADIUS or TACACS+) is "
        "configured as the primary authentication method in the default "
        "management authentication policy."
    ),
    severity=Severity.HIGH,
    framework_refs=("CIS-IOS-L2-1.4.1", "NIST-IA-2(1)", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)


# ---------------------------------------------------------------------------
# Vendor-specific remediations (returned only on FAIL for the matching vendor)
# ---------------------------------------------------------------------------

_CISCO_REMEDIATION = Remediation(
    vendor="cisco",
    guidance=(
        "Enable the AAA framework with 'aaa new-model'. "
        "Configure a default authentication list that places a remote AAA "
        "server group (RADIUS or TACACS+) as the primary method. "
        "A local fallback is recommended for resilience but must not be primary. "
        "Bind all VTY lines to the default list with 'login authentication default'."
    ),
    config_hint=(
        "aaa new-model\n"
        "aaa group server radius RADIUS-SERVERS\n"
        " server-private <radius-server-ip> auth-port 1812 acct-port 1813 key <key>\n"
        "aaa authentication login default group RADIUS-SERVERS local\n"
        "!\n"
        "line vty 0 4\n"
        " login authentication default\n"
        " transport input ssh"
    ),
)

_JUNIPER_REMEDIATION = Remediation(
    vendor="juniper",
    guidance=(
        "Configure 'authentication-order' under 'system' to list a remote "
        "authentication method (radius or tacplus) as the first entry. "
        "A local password fallback is acceptable as a subsequent entry. "
        "Ensure the corresponding radius-server or tacplus-server block is "
        "also configured under 'system'."
    ),
    config_hint=(
        "set system authentication-order [ radius password ]\n"
        "set system radius-server <ip> secret <secret>\n"
        "# OR for TACACS+:\n"
        "set system authentication-order [ tacplus password ]\n"
        "set system tacplus-server <ip> secret <secret>"
    ),
)


# ---------------------------------------------------------------------------
# Internal sentinels
# ---------------------------------------------------------------------------

_SEC_PASS = "pass"
_SEC_FAIL = "fail"
_SEC_NEEDS_REVIEW = "needs_review"

# Prefix that identifies an 'aaa authentication login default …' global item.
_AAA_DEFAULT_PREFIX = "authentication login default "

# Known remote-authentication tokens as they appear after "group ".
# Any "group <name>" token is treated as remote (named server groups too).
_REMOTE_TOKENS = frozenset({"radius", "tacplus"})

# Tokens that unambiguously mean local-only or no-auth.
_LOCAL_TOKEN = "local"
_NONE_TOKEN = "none"

# Known Juniper remote method tokens.
_JUNIPER_REMOTE = frozenset({"radius", "tacplus"})
_JUNIPER_LOCAL = "password"


# ---------------------------------------------------------------------------
# Cisco extraction helpers
# ---------------------------------------------------------------------------


def _all_aaa_items(config: NormalizedConfig) -> list[ConfigItem]:
    """Return all global items whose key is 'aaa' (case-insensitive)."""
    return [i for i in config.global_items if i.key.lower() == "aaa"]


def _has_new_model(aaa_items: list[ConfigItem]) -> bool:
    """Return True if any aaa item has value 'new-model'."""
    return any(
        i.value is not None and i.value.lower().strip() == "new-model"
        for i in aaa_items
    )


def _find_default_list_items(aaa_items: list[ConfigItem]) -> list[ConfigItem]:
    """Return items that define an 'aaa authentication login default …' list."""
    return [
        i for i in aaa_items
        if i.value is not None
        and i.value.lower().startswith(_AAA_DEFAULT_PREFIX)
    ]


def _classify_cisco_default_list(value: str) -> str:
    """Classify the primary authentication method in a default-list value string.

    Parameters
    ----------
    value:
        The full value of the 'aaa authentication login default <…>' item,
        e.g. "authentication login default group radius local".

    Returns
    -------
    One of _SEC_PASS, _SEC_FAIL, or _SEC_NEEDS_REVIEW.
    """
    # Extract the suffix after "authentication login default ".
    suffix = value[len(_AAA_DEFAULT_PREFIX):].strip().lower()

    if not suffix:
        return _SEC_NEEDS_REVIEW

    # First method token determines the primary.
    if suffix.startswith("group "):
        # Any named group (radius, tacacs+, or custom group name) is treated
        # as a remote method.
        return _SEC_PASS

    if suffix.startswith(_LOCAL_TOKEN):
        return _SEC_FAIL

    if suffix.startswith(_NONE_TOKEN):
        return _SEC_FAIL

    # Unrecognised token (e.g. krb5, kerberos, otp…).
    return _SEC_NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Juniper extraction helpers
# ---------------------------------------------------------------------------


def _parse_juniper_auth_order_tokens(value: str) -> list[str]:
    """Extract the ordered token list from a JunOS authentication-order value.

    The value has the form ``"[ radius password ]"`` or ``"[ tacplus ]"``.
    Returns a list of lowercase token strings, e.g. ``["radius", "password"]``.
    Returns an empty list if the value cannot be parsed.
    """
    stripped = value.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        inner = stripped[1:-1].strip()
        return [t.lower() for t in inner.split() if t]
    # Fallback: try to split without brackets (non-standard format).
    tokens = [t.lower() for t in stripped.split() if t]
    return tokens


def _classify_juniper_auth_order(value: str) -> str:
    """Classify the primary JunOS authentication method.

    Returns one of _SEC_PASS, _SEC_FAIL, or _SEC_NEEDS_REVIEW.
    """
    tokens = _parse_juniper_auth_order_tokens(value)
    if not tokens:
        return _SEC_NEEDS_REVIEW

    first = tokens[0]
    if first in _JUNIPER_REMOTE:
        return _SEC_PASS
    if first == _JUNIPER_LOCAL:
        return _SEC_FAIL
    # Unrecognised token.
    return _SEC_NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Rule implementation
# ---------------------------------------------------------------------------


class AaaRule(ComplianceRule):
    """Evaluates AAA-001: Remote AAA Authentication Must Be Primary."""

    control = _CONTROL

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate AAA-001 against *config*.

        Returns NOT_APPLICABLE for unsupported vendors.
        Delegates to vendor-specific extraction for Cisco and Juniper.
        """
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)

        if config.vendor == "cisco":
            return self._evaluate_cisco(config)

        if config.vendor == "juniper":
            return self._evaluate_juniper(config)

        # Vendor is listed as applicable but has no handler — should not occur
        # with the current frozenset, but handle defensively.
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
                        "but no extraction handler is implemented for AAA-001."
                    ),
                )
            ],
        )

    # ------------------------------------------------------------------
    # Cisco extraction
    # ------------------------------------------------------------------

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate AAA-001 for Cisco IOS / IOS-XE.

        Evaluation order:
        1. Confirm 'aaa new-model' is present.
        2. Find 'aaa authentication login default …' items.
        3. Handle zero / one / multiple default items.
        4. Classify the primary method.
        5. Append advisory evidence for any VTY sections referencing
           non-default named lists (informational only; does not change verdict).
        """
        aaa_items = _all_aaa_items(config)

        # ── Step 1: require aaa new-model ────────────────────────────────────
        new_model_items = [
            i for i in aaa_items
            if i.value is not None and i.value.lower().strip() == "new-model"
        ]
        if not new_model_items:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="aaa new-model + authentication login default group <remote>",
                        note=(
                            "'aaa new-model' is absent. The AAA framework is not enabled. "
                            "The device uses legacy login methods (login / login local) "
                            "on VTY lines without centralized AAA control."
                        ),
                    )
                ],
                remediation=_CISCO_REMEDIATION,
            )

        # ── Step 2: find default list items ──────────────────────────────────
        default_items = _find_default_list_items(aaa_items)

        if not default_items:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(new_model_items[0].raw_line,),
                        observed="aaa new-model present; no authentication login default list",
                        expected="authentication login default group <radius|tacacs+> [local]",
                        note=(
                            "The AAA framework is active ('aaa new-model' is present) but "
                            "no 'aaa authentication login default' list is configured. "
                            "IOS behaviour with no default list is platform-dependent. "
                            "Explicit remote-primary authentication is required."
                        ),
                    )
                ],
                remediation=_CISCO_REMEDIATION,
            )

        # ── Step 3: detect duplicate default lists ───────────────────────────
        if len(default_items) > 1:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=tuple(i.raw_line for i in default_items),
                        observed=f"{len(default_items)} 'authentication login default' items found",
                        expected="Exactly one 'authentication login default' list",
                        note=(
                            f"Found {len(default_items)} items that define "
                            "'aaa authentication login default …'. "
                            "A well-formed IOS config has exactly one default list. "
                            "The authoritative policy cannot be determined automatically. "
                            "Manual review is required."
                        ),
                    )
                ],
            )

        # ── Step 4: classify the single default list ─────────────────────────
        default_item = default_items[0]
        verdict = _classify_cisco_default_list(default_item.value)

        if verdict == _SEC_PASS:
            note = (
                "AAA is active. The default authentication list places a remote "
                f"server group as the primary method "
                f"(value: '{default_item.value}'). "
                "Control satisfied."
            )
            primary_evidence = Evidence(
                control_id=_CONTROL.control_id,
                section_name=None,
                raw_lines=(
                    new_model_items[0].raw_line,
                    default_item.raw_line,
                ),
                observed=default_item.value,
                expected="Remote method (group radius/tacacs+) as first in default list",
                note=note,
            )
            all_evidence = [primary_evidence]
            # Append advisory notes for VTY sections using non-default lists.
            all_evidence.extend(
                self._advisory_vty_evidence(config, default_item.value)
            )
            return self._build_result(
                config=config,
                status=ComplianceStatus.PASS,
                evidence=all_evidence,
                remediation=None,
            )

        if verdict == _SEC_FAIL:
            note = (
                f"AAA is active but the default list's primary method is local "
                f"or disables authentication (value: '{default_item.value}'). "
                "Centralized authentication is bypassed on every management login. "
                "A remote AAA method must be configured as the first method."
            )
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name=None,
                        raw_lines=(
                            new_model_items[0].raw_line,
                            default_item.raw_line,
                        ),
                        observed=default_item.value,
                        expected="Remote method (group radius/tacacs+) as first in default list",
                        note=note,
                    )
                ],
                remediation=_CISCO_REMEDIATION,
            )

        # verdict == _SEC_NEEDS_REVIEW
        return self._build_result(
            config=config,
            status=ComplianceStatus.NEEDS_REVIEW,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name=None,
                    raw_lines=(
                        new_model_items[0].raw_line,
                        default_item.raw_line,
                    ),
                    observed=default_item.value,
                    expected="Remote method (group radius/tacacs+) as first in default list",
                    note=(
                        f"The primary method in the default authentication list "
                        f"(value: '{default_item.value}') is not a recognised "
                        "remote (group radius/tacacs+), local, or none token. "
                        "Manual review is required to classify this configuration."
                    ),
                )
            ],
        )

    def _advisory_vty_evidence(
        self,
        config: NormalizedConfig,
        default_value: str,
    ) -> list[Evidence]:
        """Return advisory Evidence records for VTY sections that bypass the
        default list by using a named authentication list.

        These records do NOT change the verdict; they are supplementary
        information for human reviewers.
        """
        advisory: list[Evidence] = []
        for sec in config.sections:
            if not sec.name.lower().startswith("line vty"):
                continue
            for item in sec.items:
                if item.key.lower() != "login":
                    continue
                if item.value is None:
                    continue
                val_lower = item.value.lower().strip()
                # "login authentication default" is fine — uses the evaluated list.
                if val_lower == "authentication default":
                    continue
                # "login authentication <named-list>" is a potential bypass.
                if val_lower.startswith("authentication "):
                    named_list = item.value.strip()[len("authentication "):].strip()
                    advisory.append(
                        Evidence(
                            control_id=_CONTROL.control_id,
                            section_name=sec.name,
                            raw_lines=(item.raw_line,),
                            observed=item.value,
                            expected=(
                                "login authentication default "
                                "(or default list applied implicitly)"
                            ),
                            note=(
                                f"[ADVISORY] VTY section '{sec.name}' uses named "
                                f"authentication list '{named_list}' instead of the "
                                "default list. If that named list does not enforce "
                                "remote authentication it represents a bypass. "
                                "This does not affect the AAA-001 verdict, which "
                                "evaluates the default list definition only. "
                                "Review with AAA-002 when implemented."
                            ),
                        )
                    )
        return advisory

    # ------------------------------------------------------------------
    # Juniper extraction
    # ------------------------------------------------------------------

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        """Evaluate AAA-001 for Juniper JunOS.

        Uses 'authentication-order' inside the 'system' section as the
        sole evaluation signal.  Server sub-blocks (radius-server,
        tacplus-server) are explicitly NOT used — they are flattened
        into system.items with ambiguous keys.
        """
        system = config.get_section("system")

        # ── Step 1: require system section ───────────────────────────────────
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
                        expected="system { authentication-order [ radius|tacplus ... ]; }",
                        note=(
                            "No 'system' configuration block was found. "
                            "Cannot extract any authentication configuration. "
                            "The AAA policy is unknown."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        # ── Step 2: find authentication-order item ───────────────────────────
        auth_order_items = [
            i for i in system.items
            if i.key.lower() == "authentication-order"
        ]

        if not auth_order_items:
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(),
                        observed=None,
                        expected="authentication-order [ radius|tacplus ... ]",
                        note=(
                            "The 'system' section exists but contains no "
                            "'authentication-order' directive. "
                            "JunOS default when unset is local password only. "
                            "An explicit remote-primary authentication order is required."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        # ── Step 3: handle value=None (malformed) ────────────────────────────
        auth_item = auth_order_items[0]
        if auth_item.value is None:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(auth_item.raw_line,),
                        observed=None,
                        expected="authentication-order [ radius|tacplus ... ]",
                        note=(
                            "'authentication-order' directive found but has no value. "
                            "The parser returned value=None for this item. "
                            "Manual review of the raw configuration is required."
                        ),
                    )
                ],
            )

        # ── Step 4: classify primary method ──────────────────────────────────
        verdict = _classify_juniper_auth_order(auth_item.value)

        if verdict == _SEC_PASS:
            tokens = _parse_juniper_auth_order_tokens(auth_item.value)
            first = tokens[0] if tokens else "?"
            return self._build_result(
                config=config,
                status=ComplianceStatus.PASS,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(auth_item.raw_line,),
                        observed=f"authentication-order {auth_item.value}",
                        expected="Remote method (radius/tacplus) as first token",
                        note=(
                            f"'{first}' is the primary authentication method "
                            f"(full order: {auth_item.value}). "
                            "Remote-primary authentication is configured. "
                            "Control satisfied."
                        ),
                    )
                ],
                remediation=None,
            )

        if verdict == _SEC_FAIL:
            tokens = _parse_juniper_auth_order_tokens(auth_item.value)
            first = tokens[0] if tokens else "?"
            return self._build_result(
                config=config,
                status=ComplianceStatus.FAIL,
                evidence=[
                    Evidence(
                        control_id=_CONTROL.control_id,
                        section_name="system",
                        raw_lines=(auth_item.raw_line,),
                        observed=f"authentication-order {auth_item.value}",
                        expected="Remote method (radius/tacplus) as first token",
                        note=(
                            f"Local '{first}' is the primary authentication method "
                            f"(full order: {auth_item.value}). "
                            "Centralized authentication is bypassed on every login. "
                            "A remote method must be listed first."
                        ),
                    )
                ],
                remediation=_JUNIPER_REMEDIATION,
            )

        # verdict == _SEC_NEEDS_REVIEW
        tokens = _parse_juniper_auth_order_tokens(auth_item.value)
        first = tokens[0] if tokens else "?"
        return self._build_result(
            config=config,
            status=ComplianceStatus.NEEDS_REVIEW,
            evidence=[
                Evidence(
                    control_id=_CONTROL.control_id,
                    section_name="system",
                    raw_lines=(auth_item.raw_line,),
                    observed=f"authentication-order {auth_item.value}",
                    expected="Remote method (radius/tacplus) as first token",
                    note=(
                        f"The first authentication-order token '{first}' is not "
                        "a recognised method (radius, tacplus, password). "
                        "Manual review is required to classify this configuration."
                    ),
                )
            ],
        )
