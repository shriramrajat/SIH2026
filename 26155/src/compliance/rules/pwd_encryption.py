"""
PWD-001: Privileged Exec / Root Password Must Use Strong Hashing.
"""

from src.compliance.model import (
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    Remediation,
    Severity,
)
from src.compliance.rules.base import ComplianceRule, SecurityControl
from src.normalization.model import NormalizedConfig


class PwdEncryptionRule(ComplianceRule):
    """Evaluates whether the privileged management credential uses strong hashing."""

    control = SecurityControl(
        control_id="PWD-001",
        control_name="Privileged Exec / Root Password Must Use Strong Hashing",
        description=(
            "Detects weak or deprecated password hashing for the highest-privilege "
            "management credential. Prevents offline password cracking."
        ),
        severity=Severity.HIGH,
        framework_refs=("CIS-IOS-L2-2.1.1", "CIS-JUNOS-L2-2.1.1"),
        applicable_vendors=frozenset({"cisco", "juniper"}),
    )

    def evaluate(self, config: NormalizedConfig) -> ComplianceResult:
        if not self.control.applies_to(config.vendor):
            return self._not_applicable(config)

        if config.vendor == "cisco":
            return self._evaluate_cisco(config)
        elif config.vendor == "juniper":
            return self._evaluate_juniper(config)

        return self._not_applicable(config)

    def _sanitize(self, value: str, raw_line: str) -> tuple[str, str]:
        """Redact sensitive password/hash material from evidence strings."""
        if not value:
            return value, raw_line
        
        parts = value.split(" ", 2)
        if len(parts) >= 2 and parts[0] == "secret":
            # Cisco: "secret 5 $1$abc" -> "secret 5 [REDACTED]"
            safe_val = f"{parts[0]} {parts[1]} [REDACTED]"
            safe_raw = raw_line.replace(value, safe_val)
            return safe_val, safe_raw
        elif parts[0] == "password":
            # Cisco: "password cleartext" -> "password [REDACTED]"
            safe_val = "password [REDACTED]"
            safe_raw = raw_line.replace(value, safe_val)
            return safe_val, safe_raw
        elif value.startswith('"') and value.endswith('"'):
            # Juniper: "$6$hash"
            prefix_len = 3 if value.startswith('"$') and len(value) > 3 and value[3] == '$' else 1
            safe_val = f'{value[:prefix_len]}[REDACTED]"'
            safe_raw = raw_line.replace(value, safe_val)
            return safe_val, safe_raw
        
        # Fallback for unrecognized formats to ensure no leak
        safe_val = "[REDACTED]"
        safe_raw = raw_line.replace(value, safe_val)
        return safe_val, safe_raw

    def _evaluate_cisco(self, config: NormalizedConfig) -> ComplianceResult:
        enable_items = [i for i in config.global_items if i.key.lower() == "enable"]

        if not enable_items:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=self.control.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="An 'enable' directive with strong hashing (e.g. secret 8 or 9)",
                        note="No 'enable' directive was found in the configuration.",
                    )
                ],
            )

        evidence_list = []
        has_weak = False
        has_strong = False
        has_unknown = False

        for item in enable_items:
            val = item.value or ""
            if not item.value:
                safe_val, safe_raw = "[REDACTED]", "[REDACTED]"
            else:
                safe_val, safe_raw = self._sanitize(val, item.raw_line)

            if val.startswith("secret 8") or val.startswith("secret 9"):
                has_strong = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name=None,
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Strong password hashing is configured.",
                    )
                )
            elif val.startswith("secret 5") or val.startswith("secret 7") or val.startswith("password ") or val.startswith("secret 0"):
                has_weak = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name=None,
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Weak or deprecated password hashing mechanism detected.",
                    )
                )
            else:
                has_unknown = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name=None,
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Unrecognized or malformed enable directive.",
                    )
                )

        if has_weak:
            status = ComplianceStatus.FAIL
            remediation = Remediation(
                vendor="cisco",
                guidance="Migrate the privileged credential to a supported strong password hashing mechanism appropriate for the platform (e.g., secret 8 or 9).",
            )
        elif has_strong:
            status = ComplianceStatus.PASS
            remediation = None
        else:
            status = ComplianceStatus.NEEDS_REVIEW
            remediation = None

        return self._build_result(
            config=config,
            status=status,
            evidence=evidence_list,
            remediation=remediation,
        )

    def _evaluate_juniper(self, config: NormalizedConfig) -> ComplianceResult:
        system = config.get_section("system")
        if not system:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=self.control.control_id,
                        section_name=None,
                        raw_lines=(),
                        observed=None,
                        expected="System section containing 'encrypted-password'",
                        note="The 'system' section is missing.",
                    )
                ],
            )

        items = [i for i in system.items if i.key.lower() == "encrypted-password"]

        if not items:
            return self._build_result(
                config=config,
                status=ComplianceStatus.NEEDS_REVIEW,
                evidence=[
                    Evidence(
                        control_id=self.control.control_id,
                        section_name="system",
                        raw_lines=(),
                        observed=None,
                        expected="An 'encrypted-password' directive with strong hashing (e.g. $5$ or $6$)",
                        note="No 'encrypted-password' directive was found in the system section.",
                    )
                ],
            )

        evidence_list = []
        has_weak = False
        has_strong = False
        has_unknown = False

        for item in items:
            val = item.value
            if not val:
                has_unknown = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name="system",
                        raw_lines=("[REDACTED]",),
                        observed="[REDACTED]",
                        expected="Strong hashing mechanism",
                        note="The 'encrypted-password' directive is empty.",
                    )
                )
                continue

            safe_val, safe_raw = self._sanitize(val, item.raw_line)

            if val.startswith('"$5$') or val.startswith('"$6$') or val.startswith('"$8$') or val.startswith('"$9$'):
                has_strong = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name="system",
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Strong password hashing is configured.",
                    )
                )
            elif val.startswith('"$1$'):
                has_weak = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name="system",
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Weak or deprecated password hashing mechanism detected (MD5).",
                    )
                )
            else:
                has_unknown = True
                evidence_list.append(
                    Evidence(
                        control_id=self.control.control_id,
                        section_name="system",
                        raw_lines=(safe_raw,),
                        observed=safe_val,
                        expected="Strong hashing mechanism",
                        note="Unrecognized or malformed encrypted-password format.",
                    )
                )

        if has_weak:
            status = ComplianceStatus.FAIL
            remediation = Remediation(
                vendor="juniper",
                guidance="Replace the weak root password hash with a modern supported password-hashing configuration (e.g., SHA-512).",
            )
        elif has_strong and not has_unknown:
            status = ComplianceStatus.PASS
            remediation = None
        else:
            status = ComplianceStatus.NEEDS_REVIEW
            remediation = None

        return self._build_result(
            config=config,
            status=status,
            evidence=evidence_list,
            remediation=remediation,
        )
