"""
normalization.model
~~~~~~~~~~~~~~~~~~~

Vendor-neutral representation of a parsed network-device configuration.

Design intent
-------------
Every vendor parser (Cisco, Juniper, …) converts its raw output into a
``NormalizedConfig`` object.  Downstream consumers (compliance engine,
reports, etc.) work exclusively with this model — they never import
vendor-specific parsers.

Keep this model simple.  Add fields only when a concrete use-case demands
them.  Do not embed compliance logic here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConfigItem:
    """A single key/value configuration entry within a section.

    Parameters
    ----------
    key:
        The configuration directive name (e.g. ``"ip ssh version"``).
    value:
        The raw or lightly cleaned value string (e.g. ``"2"``).
        ``None`` when the directive is a flag with no associated value.
    raw_line:
        The original, unmodified source line.  Useful for debugging and
        for producing diffs against the original file.
    """

    key: str
    value: str | None
    raw_line: str


@dataclass
class ConfigSection:
    """A named group of related configuration items.

    Sections map loosely to the block structure of vendor configurations.
    For Cisco IOS, top-level stanzas such as ``line vty 0 4`` or
    ``interface GigabitEthernet0/0`` become sections.

    Parameters
    ----------
    name:
        Human-readable section identifier (e.g. ``"line vty 0 4"``).
    items:
        Ordered list of :class:`ConfigItem` entries within this section.
    metadata:
        Optional free-form dict for vendor-specific extras that do not fit
        the generic key/value model.  Consumers should treat this as
        advisory; do not rely on it for compliance decisions.
    """

    name: str
    items: list[ConfigItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedConfig:
    """Vendor-neutral configuration representation.

    Parameters
    ----------
    vendor:
        Lowercase vendor identifier (e.g. ``"cisco"``).
    hostname:
        Device hostname if present in the configuration, otherwise ``None``.
    sections:
        Ordered list of top-level configuration sections.
    global_items:
        Configuration items that do not belong to any sub-section
        (i.e. top-level directives).
    raw_config:
        The original configuration text.  Stored for traceability.
    source_file:
        Absolute or relative path to the configuration file that was parsed,
        or ``None`` when the config was loaded from a string rather than from
        the filesystem.  Preserved so that compliance findings can reference
        the file that produced them — required for frontend traceability.
    """

    vendor: str
    hostname: str | None
    sections: list[ConfigSection] = field(default_factory=list)
    global_items: list[ConfigItem] = field(default_factory=list)
    raw_config: str = ""
    source_file: str | None = None

    def get_global(self, key: str) -> ConfigItem | None:
        """Return the first global item whose key matches *key*, or ``None``."""
        key_lower = key.lower()
        return next(
            (item for item in self.global_items if item.key.lower() == key_lower),
            None,
        )

    def get_section(self, name: str) -> ConfigSection | None:
        """Return the first section whose name matches *name*, or ``None``."""
        name_lower = name.lower()
        return next(
            (s for s in self.sections if s.name.lower() == name_lower),
            None,
        )
