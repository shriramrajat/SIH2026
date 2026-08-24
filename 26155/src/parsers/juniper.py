"""
parsers.juniper
~~~~~~~~~~~~~~~

Foundation parser for Juniper JunOS configuration files.

Scope (today)
-------------
- Detect and strip JunOS comment lines (``##`` / ``#``).
- Extract the device hostname from ``system { host-name <name>; }``.
- Identify top-level configuration blocks (``system``, ``interfaces``,
  ``routing-options``, ``security``, etc.) as :class:`ConfigSection` objects.
- Collect top-level non-block directives as global items.
- Capture first-level child statements of each block as section items.
- Handle nested blocks without recursion errors by tracking brace depth.
- Avoid treating bare ``{`` or ``}`` lines as configuration values.
- Preserve every raw line in ``raw_config`` for traceability.

Out of scope (deliberately)
---------------------------
- Full JunOS grammar for every directive.
- Deep recursive parsing of arbitrarily nested blocks.
- Security compliance analysis.
- ACL / route / BGP semantic extraction.

Design conventions
------------------
Mirrors the Cisco parser:
  - All logic is private helpers + one public ``parse_juniper()`` entry point.
  - Returns :class:`~src.normalization.model.NormalizedConfig`; no vendor-
    specific fields are added to the normalization model.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# JunOS comment lines start with '#' (single or double).
_COMMENT_RE = re.compile(r"^\s*#")

# A line that is *only* a closing brace (possibly with a trailing semicolon).
_CLOSE_BRACE_RE = re.compile(r"^\s*\}\s*;?\s*$")

# A line whose stripped form ends with '{' — marks the start of a JunOS block.
# Examples:
#   system {
#   ge-0/0/0 {
#   security-zone trust {
_OPEN_BRACE_RE = re.compile(r"^(?P<name>.+?)\s*\{\s*$")

# Semicolon-terminated directives (leaf statements).
#   host-name LAB-SRX-01;
#   root-login deny;
_LEAF_RE = re.compile(r"^(?P<key>\S+(?:\s+\S+)*?)\s+(?P<value>.+?);\s*$")
_FLAG_RE = re.compile(r"^(?P<key>\S+(?:\s+\S+)*);\s*$")

# Recognised top-level JunOS block keywords.  Unknown blocks are still
# captured as sections — the set is just for documentation purposes.
_TOP_LEVEL_BLOCKS = {
    "system",
    "interfaces",
    "routing-options",
    "routing-instances",
    "security",
    "protocols",
    "policy-options",
    "firewall",
    "applications",
    "vlans",
    "chassis",
    "snmp",
    "access",
    "groups",
    "forwarding-options",
}


class _RawLine(NamedTuple):
    """Typed wrapper for a single raw configuration line."""

    number: int    # 1-based line number in the original file
    text: str      # original text, no trailing newline
    stripped: str  # text.strip()


def _classify_lines(raw_config: str) -> list[_RawLine]:
    """Split *raw_config* into :class:`_RawLine` objects."""
    return [
        _RawLine(number=i, text=t, stripped=t.strip())
        for i, t in enumerate(raw_config.splitlines(), start=1)
    ]


def _is_noise(line: _RawLine) -> bool:
    """Return ``True`` for blank lines and comment-only lines."""
    if not line.stripped:
        return True
    if _COMMENT_RE.match(line.text):
        return True
    return False


def _is_open_brace(line: _RawLine) -> re.Match | None:
    """Return the regex match if *line* opens a JunOS block, else ``None``."""
    return _OPEN_BRACE_RE.match(line.stripped)


def _is_close_brace(line: _RawLine) -> bool:
    """Return ``True`` if *line* closes a JunOS block."""
    return bool(_CLOSE_BRACE_RE.match(line.stripped))


def _make_item(line: _RawLine) -> ConfigItem | None:
    """Convert a leaf JunOS statement into a :class:`ConfigItem`.

    Returns ``None`` for structural lines (bare braces) that carry no value.
    """
    text = line.stripped

    # Bare braces are structural -- never emit them as config items.
    if text in ("{", "}", "};"):
        return None

    # Leaf with value:  key value;
    m = _LEAF_RE.match(text)
    if m:
        return ConfigItem(key=m.group("key"), value=m.group("value"), raw_line=line.text)

    # Flag / presence statement:  keyword;
    m = _FLAG_RE.match(text)
    if m:
        return ConfigItem(key=m.group("key"), value=None, raw_line=line.text)

    # Fallback: treat whole stripped text as key with no value.
    # Keeps unusual directives from crashing the parser.
    return ConfigItem(key=text, value=None, raw_line=line.text)


def _extract_hostname(lines: list[_RawLine]) -> str | None:
    """Return the device hostname from a JunOS config, or ``None``.

    JunOS stores the hostname as::

        system {
            host-name <name>;
        }

    A lightweight scan for ``host-name <value>;`` is sufficient because
    ``host-name`` only appears under the ``system`` hierarchy.
    """
    for line in lines:
        m = re.match(r"host-name\s+(\S+);", line.stripped)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------


def parse_juniper(raw_config: str) -> NormalizedConfig:
    """Parse a Juniper JunOS configuration string.

    Parameters
    ----------
    raw_config:
        Full text of the configuration file.

    Returns
    -------
    NormalizedConfig
        Vendor-neutral representation populated with the data extractable
        by this foundation parser.

    Notes
    -----
    JunOS uses a hierarchical brace-delimited syntax rather than the
    indentation-based stanza style of Cisco IOS.  This parser uses a
    *brace-depth counter* to navigate the hierarchy without recursion:

    - Depth 0: between top-level blocks (global scope).
    - Depth 1: inside a top-level block (section scope).
    - Depth >= 2: nested sub-blocks — parsed shallowly; leaf items are
      captured under the enclosing top-level section to preserve structure.
    """
    lines = _classify_lines(raw_config)
    hostname = _extract_hostname(lines)

    global_items: list[ConfigItem] = []
    sections: list[ConfigSection] = []

    current_section: ConfigSection | None = None
    depth: int = 0  # brace nesting depth

    for line in lines:
        if _is_noise(line):
            continue

        # ---- closing brace -------------------------------------------------
        if _is_close_brace(line):
            depth -= 1
            if depth < 0:
                # Malformed / truncated config — reset gracefully.
                depth = 0
            if depth == 0 and current_section is not None:
                # Top-level block is closing; flush the current section.
                sections.append(current_section)
                current_section = None
            # Braces never become config items.
            continue

        # ---- opening brace -------------------------------------------------
        open_m = _is_open_brace(line)
        if open_m:
            block_name = open_m.group("name").strip()
            depth += 1
            if depth == 1:
                # Opening a new top-level block.
                if current_section is not None:
                    sections.append(current_section)
                current_section = ConfigSection(name=block_name)
            # Depth >= 2: nested block — children attach to current section.
            continue

        # ---- leaf / directive ----------------------------------------------
        item = _make_item(line)
        if item is None:
            continue

        if depth == 0:
            # True global directive (rare in JunOS, e.g. bare ``version``).
            global_items.append(item)
        else:
            if current_section is not None:
                current_section.items.append(item)
            else:
                # Orphaned item (depth > 0 but no open section) — treat global.
                global_items.append(item)

    # Flush any section still open at EOF (handles truncated configs).
    if current_section is not None:
        sections.append(current_section)

    return NormalizedConfig(
        vendor="juniper",
        hostname=hostname,
        sections=sections,
        global_items=global_items,
        raw_config=raw_config,
    )
