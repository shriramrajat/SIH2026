"""
parsers.cisco
~~~~~~~~~~~~~

Foundation parser for Cisco IOS / IOS-XE configuration files.

Scope (today)
-------------
- Extract hostname.
- Identify top-level section boundaries (stanzas that start in column 0
  and contain indented sub-commands, such as ``line vty``, ``interface``,
  ``router ospf``, etc.).
- Collect top-level (global) directives.
- Preserve every raw line for traceability.

Out of scope (deliberately)
---------------------------
- Full command grammar for every Cisco IOS directive.
- Security compliance analysis.
- ACL/route/BGP parsing.

This foundation can be extended incrementally as new compliance rules require
deeper parsing of specific commands.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Lines that are pure noise in IOS configs and carry no semantic content.
_COMMENT_OR_SEPARATOR = re.compile(r"^!.*$|^$")

# A section header is a line that starts at column 0 and is immediately
# followed by at least one indented line.  Common Cisco examples:
#   interface GigabitEthernet0/0
#   line vty 0 4
#   router ospf 1
_SECTION_STARTERS = re.compile(
    r"^(interface|line|router|ip vrf|vlan|crypto|policy-map|class-map"
    r"|route-map|control-plane|banner)\b",
    re.IGNORECASE,
)


class _RawLine(NamedTuple):
    """Typed wrapper for a single raw configuration line."""

    number: int  # 1-based line number in the original file
    text: str  # original text, no newline
    is_indented: bool  # True when the line starts with whitespace


def _classify_lines(raw_config: str) -> list[_RawLine]:
    """Split *raw_config* into :class:`_RawLine` objects."""
    result: list[_RawLine] = []
    for i, text in enumerate(raw_config.splitlines(), start=1):
        is_indented = bool(text) and text[0] in (" ", "\t")
        result.append(_RawLine(number=i, text=text, is_indented=is_indented))
    return result


def _extract_hostname(lines: list[_RawLine]) -> str | None:
    """Return the hostname value from *lines*, or ``None`` if absent."""
    for line in lines:
        stripped = line.text.strip()
        if stripped.lower().startswith("hostname "):
            parts = stripped.split(None, 1)
            return parts[1] if len(parts) == 2 else None  # noqa: SIM910
    return None


def _make_item(line: _RawLine) -> ConfigItem:
    """Convert a :class:`_RawLine` into a :class:`ConfigItem`.

    Splits on the first whitespace to separate the directive key from its
    value.  For multi-word directives (e.g. ``ip ssh version 2``) the key
    retains the full directive name and the last token becomes the value.
    """
    text = line.text.strip()
    parts = text.split(None, 1)
    if len(parts) == 1:
        return ConfigItem(key=parts[0], value=None, raw_line=line.text)
    return ConfigItem(key=parts[0], value=parts[1], raw_line=line.text)


def _is_noise(line: _RawLine) -> bool:
    """Return ``True`` for lines that carry no configuration semantics."""
    return bool(_COMMENT_OR_SEPARATOR.match(line.text.strip()))


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------


def parse_cisco(raw_config: str) -> NormalizedConfig:
    """Parse a Cisco IOS / IOS-XE configuration string.

    Parameters
    ----------
    raw_config:
        Full text of the configuration file.

    Returns
    -------
    NormalizedConfig
        Vendor-neutral representation populated with the data extractable
        by this foundation parser.
    """
    lines = _classify_lines(raw_config)
    hostname = _extract_hostname(lines)

    global_items: list[ConfigItem] = []
    sections: list[ConfigSection] = []

    current_section: ConfigSection | None = None

    for line in lines:
        if _is_noise(line):
            # Skip blank lines and IOS comment markers (``!``).
            # If we are inside a section, a bare ``!`` or blank line signals
            # the end of that section.
            if current_section is not None:
                sections.append(current_section)
                current_section = None
            continue

        if line.is_indented:
            # Sub-command belonging to the current section.
            if current_section is not None:
                current_section.items.append(_make_item(line))
            else:
                # Orphaned indented line — treat as global to be safe.
                global_items.append(_make_item(line))
            continue

        # Non-indented, non-noise line.
        text = line.text.strip()

        if text.lower() == "end":
            # IOS end marker — flush any open section.
            if current_section is not None:
                sections.append(current_section)
                current_section = None
            continue

        if _SECTION_STARTERS.match(text):
            # Flush the previous section before opening a new one.
            if current_section is not None:
                sections.append(current_section)
            current_section = ConfigSection(name=text)
            continue

        # Plain top-level directive (e.g. ``hostname``, ``ip ssh version 2``).
        global_items.append(_make_item(line))

    # Flush any section still open at EOF.
    if current_section is not None:
        sections.append(current_section)

    return NormalizedConfig(
        vendor="cisco",
        hostname=hostname,
        sections=sections,
        global_items=global_items,
        raw_config=raw_config,
    )
