"""
tests/unit/test_normalization.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the vendor-neutral normalization model
(:mod:`src.normalization.model`).

These tests verify the data model directly — they do not depend on any
vendor parser.
"""

import pytest

from src.normalization.model import ConfigItem, ConfigSection, NormalizedConfig


# ---------------------------------------------------------------------------
# ConfigItem
# ---------------------------------------------------------------------------


class TestConfigItem:
    """Tests for :class:`ConfigItem`."""

    def test_create_with_value(self) -> None:
        item = ConfigItem(key="ip", value="ssh version 2", raw_line="ip ssh version 2")
        assert item.key == "ip"
        assert item.value == "ssh version 2"
        assert item.raw_line == "ip ssh version 2"

    def test_create_without_value(self) -> None:
        item = ConfigItem(key="no shutdown", value=None, raw_line="no shutdown")
        assert item.value is None


# ---------------------------------------------------------------------------
# ConfigSection
# ---------------------------------------------------------------------------


class TestConfigSection:
    """Tests for :class:`ConfigSection`."""

    def test_empty_section(self) -> None:
        section = ConfigSection(name="line vty 0 4")
        assert section.name == "line vty 0 4"
        assert section.items == []
        assert section.metadata == {}

    def test_section_with_items(self) -> None:
        item = ConfigItem(
            key="transport", value="input ssh", raw_line=" transport input ssh"
        )
        section = ConfigSection(name="line vty 0 4", items=[item])
        assert len(section.items) == 1
        assert section.items[0].key == "transport"

    def test_section_metadata(self) -> None:
        section = ConfigSection(name="test", metadata={"vlan_id": 10})
        assert section.metadata["vlan_id"] == 10


# ---------------------------------------------------------------------------
# NormalizedConfig
# ---------------------------------------------------------------------------


class TestNormalizedConfig:
    """Tests for :class:`NormalizedConfig`."""

    def test_minimal_construction(self) -> None:
        cfg = NormalizedConfig(vendor="cisco", hostname="LAB-ROUTER")
        assert cfg.vendor == "cisco"
        assert cfg.hostname == "LAB-ROUTER"
        assert cfg.global_items == []
        assert cfg.sections == []
        assert cfg.raw_config == ""

    def test_hostname_can_be_none(self) -> None:
        cfg = NormalizedConfig(vendor="cisco", hostname=None)
        assert cfg.hostname is None

    def test_get_global_finds_existing_item(self) -> None:
        item = ConfigItem(key="version", value="17.9", raw_line="version 17.9")
        cfg = NormalizedConfig(
            vendor="cisco", hostname=None, global_items=[item]
        )
        found = cfg.get_global("version")
        assert found is item

    def test_get_global_case_insensitive(self) -> None:
        item = ConfigItem(key="Version", value="17.9", raw_line="Version 17.9")
        cfg = NormalizedConfig(
            vendor="cisco", hostname=None, global_items=[item]
        )
        assert cfg.get_global("version") is item
        assert cfg.get_global("VERSION") is item

    def test_get_global_returns_none_for_missing_key(self) -> None:
        cfg = NormalizedConfig(vendor="cisco", hostname=None)
        assert cfg.get_global("nonexistent") is None

    def test_get_section_finds_section(self) -> None:
        section = ConfigSection(name="line vty 0 4")
        cfg = NormalizedConfig(
            vendor="cisco", hostname=None, sections=[section]
        )
        found = cfg.get_section("line vty 0 4")
        assert found is section

    def test_get_section_case_insensitive(self) -> None:
        section = ConfigSection(name="Line VTY 0 4")
        cfg = NormalizedConfig(
            vendor="cisco", hostname=None, sections=[section]
        )
        assert cfg.get_section("line vty 0 4") is section

    def test_get_section_returns_none_for_missing_section(self) -> None:
        cfg = NormalizedConfig(vendor="cisco", hostname=None)
        assert cfg.get_section("interface GigabitEthernet0/0") is None

    def test_raw_config_stored(self) -> None:
        raw = "hostname LAB-ROUTER\n"
        cfg = NormalizedConfig(vendor="cisco", hostname="LAB-ROUTER", raw_config=raw)
        assert cfg.raw_config == raw

    def test_multiple_sections(self) -> None:
        s1 = ConfigSection(name="line vty 0 4")
        s2 = ConfigSection(name="interface GigabitEthernet0/0")
        cfg = NormalizedConfig(
            vendor="cisco", hostname=None, sections=[s1, s2]
        )
        assert len(cfg.sections) == 2

    def test_vendor_is_stored(self) -> None:
        """Vendor field supports any string — future parsers can use their own."""
        cfg = NormalizedConfig(vendor="future-vendor", hostname=None)
        assert cfg.vendor == "future-vendor"
