from typing import Literal


Vendor = Literal["cisco", "juniper", "unknown"]

# ---------------------------------------------------------------------------
# Juniper JunOS marker patterns
# ---------------------------------------------------------------------------
#
# JunOS-specific markers used for detection.  All are checked against the
# stripped, lowercased version of each line unless noted.
#
# Chosen markers and their rationale:
#   "## "     – JunOS file-level comment header (double-hash); extremely rare
#               in non-JunOS configs.  Checked on the raw (non-lowercased)
#               stripped line because the prefix is case-sensitive in practice.
#   "system {" – The root-level system block opener.  Present in virtually
#               every JunOS config.  The brace distinguishes it from a Cisco
#               "system" keyword (which Cisco IOS does not use at global scope).
#   "interfaces {" – Juniper top-level interfaces block.  Not used by Cisco
#               at global scope in the same brace-delimited syntax.
#   "security {" – Juniper top-level security block.  Same rationale.
#
# Markers deliberately NOT used:
#   "version X;" – The semicolon-terminated form could overlap with IOS banners
#               or other configs; excluded to avoid false positives.
# ---------------------------------------------------------------------------

_JUNIPER_RAW_MARKERS = (
    "## ",   # JunOS double-hash file comment (raw prefix, case-sensitive)
)

_JUNIPER_LOWER_MARKERS = (
    "system {",
    "interfaces {",
    "security {",
    "routing-options {",
    "protocols {",
    "authentication-order",
    "root-authentication",
)

# ---------------------------------------------------------------------------
# Cisco IOS / IOS-XE marker patterns
# ---------------------------------------------------------------------------
#
# The existing first-match behavior is preserved.  Cisco markers are checked
# before Juniper ones so that a config with both (ambiguous) resolves to Cisco,
# consistent with the prior implementation.
# ---------------------------------------------------------------------------

_CISCO_LOWER_MARKERS = (
    "version ",       # IOS version header: "version 17.9" (no semicolon)
    "hostname ",      # Global hostname directive
    "enable secret ", # Privileged credential
    "ip ssh version ",# SSH version directive
)



def detect_vendor(config: str) -> Vendor:
    """Detect the vendor from configuration content.

    Uses a first-match scan over all lines.  Cisco markers are evaluated
    before Juniper markers, so an ambiguous config that contains markers for
    both resolves to ``"cisco"`` — this preserves the prior first-match
    behaviour.

    Parameters
    ----------
    config:
        Raw configuration text.

    Returns
    -------
    Vendor
        ``"cisco"`` or ``"juniper"`` if a positive match is found,
        ``"unknown"`` otherwise.
    """
    lines = config.splitlines()

    for line in lines:
        stripped = line.strip()
        normalized = stripped.lower()

        # ---- Cisco checks (evaluated first) --------------------------------
        for marker in _CISCO_LOWER_MARKERS:
            if normalized.startswith(marker) and normalized[len(marker):].strip():
                return "cisco"

        # ---- Juniper raw-prefix checks (case-sensitive) --------------------
        for marker in _JUNIPER_RAW_MARKERS:
            if stripped.startswith(marker):
                return "juniper"

        # ---- Juniper lowercased marker checks ------------------------------
        for marker in _JUNIPER_LOWER_MARKERS:
            if normalized == marker.rstrip() or normalized.startswith(marker):
                return "juniper"

        if normalized.startswith("host-name ") and normalized.endswith(";"):
            return "juniper"

    return "unknown"