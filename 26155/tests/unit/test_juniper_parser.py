"""
tests/unit/test_juniper_parser.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the Juniper JunOS foundation parser
(:func:`src.parsers.juniper.parse_juniper`).
"""

from pathlib import Path

import pytest

from src.parsers.juniper import parse_juniper
from src.normalization.model import NormalizedConfig, ConfigSection, ConfigItem


FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "juniper-basic.conf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------


class TestParseJuniperReturnType:
    """The parser always returns a :class:`NormalizedConfig` object."""

    def test_returns_normalized_config(self) -> None:
        result = parse_juniper("system {\n    host-name R1;\n}\n")
        assert isinstance(result, NormalizedConfig)

    def test_vendor_is_juniper(self) -> None:
        result = parse_juniper("system {\n    host-name R1;\n}\n")
        assert result.vendor == "juniper"


# ---------------------------------------------------------------------------
# Hostname extraction
# ---------------------------------------------------------------------------


class TestHostnameExtraction:
    """Tests for hostname identification within JunOS configurations."""

    def test_extracts_hostname(self) -> None:
        config = "system {\n    host-name CORE-SRX-01;\n}\n"
        result = parse_juniper(config)
        assert result.hostname == "CORE-SRX-01"

    def test_hostname_is_none_when_absent(self) -> None:
        config = "system {\n    time-zone UTC;\n}\n"
        result = parse_juniper(config)
        assert result.hostname is None

    def test_extracts_hostname_from_fixture(self) -> None:
        result = parse_juniper(_load_fixture())
        assert result.hostname == "LAB-SRX-01"

    def test_hostname_with_hyphens(self) -> None:
        config = "system {\n    host-name lab-srx-core-01;\n}\n"
        result = parse_juniper(config)
        assert result.hostname == "lab-srx-core-01"


# ---------------------------------------------------------------------------
# Global directives
# ---------------------------------------------------------------------------


class TestGlobalItems:
    """Tests for top-level (non-section) configuration directives."""

    def test_global_items_is_list(self) -> None:
        result = parse_juniper("")
        assert isinstance(result.global_items, list)

    def test_version_line_in_global_items(self) -> None:
        config = "version 22.4R1.10;\nsystem {\n    host-name R1;\n}\n"
        result = parse_juniper(config)
        keys = [item.key.lower() for item in result.global_items]
        assert "version" in keys

    def test_global_item_has_value(self) -> None:
        config = "version 22.4R1.10;\n"
        result = parse_juniper(config)
        item = result.get_global("version")
        assert item is not None
        assert item.value == "22.4R1.10"

    def test_get_global_returns_none_for_absent_key(self) -> None:
        result = parse_juniper("version 22.4R1.10;\n")
        assert result.get_global("nonexistent-directive") is None


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------


class TestSectionParsing:
    """Tests for top-level block detection."""

    def test_sections_is_list(self) -> None:
        result = parse_juniper("")
        assert isinstance(result.sections, list)

    def test_system_block_becomes_section(self) -> None:
        config = "system {\n    host-name R1;\n}\n"
        result = parse_juniper(config)
        section_names = [s.name.lower() for s in result.sections]
        assert "system" in section_names

    def test_interfaces_block_becomes_section(self) -> None:
        config = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        description \"WAN\";\n"
            "    }\n"
            "}\n"
        )
        result = parse_juniper(config)
        section_names = [s.name.lower() for s in result.sections]
        assert "interfaces" in section_names

    def test_routing_options_block_becomes_section(self) -> None:
        config = "routing-options {\n    router-id 192.0.2.1;\n}\n"
        result = parse_juniper(config)
        section_names = [s.name.lower() for s in result.sections]
        assert "routing-options" in section_names

    def test_security_block_becomes_section(self) -> None:
        config = "security {\n    zones {\n    }\n}\n"
        result = parse_juniper(config)
        section_names = [s.name.lower() for s in result.sections]
        assert "security" in section_names

    def test_fixture_contains_multiple_sections(self) -> None:
        result = parse_juniper(_load_fixture())
        assert len(result.sections) >= 4

    def test_get_section_helper(self) -> None:
        config = "routing-options {\n    router-id 10.0.0.1;\n}\n"
        result = parse_juniper(config)
        section = result.get_section("routing-options")
        assert section is not None
        assert isinstance(section, ConfigSection)

    def test_get_section_returns_none_for_absent_section(self) -> None:
        result = parse_juniper("system {\n    host-name R1;\n}\n")
        assert result.get_section("firewall") is None

    def test_section_items_captured(self) -> None:
        config = (
            "routing-options {\n"
            "    router-id 192.0.2.100;\n"
            "    autonomous-system 65001;\n"
            "}\n"
        )
        result = parse_juniper(config)
        section = result.get_section("routing-options")
        assert section is not None
        item_keys = [item.key.lower() for item in section.items]
        assert "router-id" in item_keys
        assert "autonomous-system" in item_keys


# ---------------------------------------------------------------------------
# SSH / services configuration
# ---------------------------------------------------------------------------


class TestSSHConfiguration:
    """Tests specific to SSH-related extraction within system services."""

    def test_ssh_items_captured_under_system(self) -> None:
        config = (
            "system {\n"
            "    services {\n"
            "        ssh {\n"
            "            root-login deny;\n"
            "            protocol-version v2;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = parse_juniper(config)
        system = result.get_section("system")
        assert system is not None
        # Nested items roll up to the top-level section.
        item_keys = [item.key.lower() for item in system.items]
        assert "root-login" in item_keys
        assert "protocol-version" in item_keys

    def test_fixture_has_ssh_items_in_system(self) -> None:
        result = parse_juniper(_load_fixture())
        system = result.get_section("system")
        assert system is not None
        item_keys = [item.key.lower() for item in system.items]
        assert "root-login" in item_keys


# ---------------------------------------------------------------------------
# Nested block handling
# ---------------------------------------------------------------------------


class TestNestedBlocks:
    """Parser must not crash on deeply-nested JunOS structures."""

    def test_nested_blocks_do_not_crash(self) -> None:
        config = (
            "security {\n"
            "    zones {\n"
            "        security-zone trust {\n"
            "            interfaces {\n"
            "                ge-0/0/1.0;\n"
            "            }\n"
            "        }\n"
            "        security-zone untrust {\n"
            "            interfaces {\n"
            "                ge-0/0/0.0;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = parse_juniper(config)
        assert isinstance(result, NormalizedConfig)

    def test_nested_items_roll_up_to_top_section(self) -> None:
        """Items inside nested blocks attach to the enclosing top-level section."""
        config = (
            "interfaces {\n"
            "    ge-0/0/0 {\n"
            "        description \"WAN uplink\";\n"
            "        unit 0 {\n"
            "            family inet {\n"
            "                address 203.0.113.2/30;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        result = parse_juniper(config)
        iface = result.get_section("interfaces")
        assert iface is not None
        item_keys = [item.key.lower() for item in iface.items]
        assert "description" in item_keys
        assert "address" in item_keys


# ---------------------------------------------------------------------------
# Comment and blank-line handling
# ---------------------------------------------------------------------------


class TestCommentsAndBlanks:
    """Comments and blank lines must be silently ignored."""

    def test_hash_comments_ignored(self) -> None:
        config = (
            "## This is a JunOS file-level comment\n"
            "# Another comment\n"
            "system {\n"
            "    host-name R1;  # inline note\n"
            "    ## section comment\n"
            "    time-zone UTC;\n"
            "}\n"
        )
        result = parse_juniper(config)
        assert result.hostname == "R1"
        system = result.get_section("system")
        assert system is not None

    def test_blank_lines_ignored(self) -> None:
        config = "\n\nsystem {\n\n    host-name R1;\n\n}\n\n"
        result = parse_juniper(config)
        assert result.hostname == "R1"
        assert len(result.sections) == 1

    def test_mixed_comments_and_blanks_with_real_config(self) -> None:
        result = parse_juniper(_load_fixture())
        # Fixture has both ## comments and blank lines — should parse cleanly.
        assert result.hostname == "LAB-SRX-01"
        assert len(result.sections) >= 1


# ---------------------------------------------------------------------------
# Braces not treated as values
# ---------------------------------------------------------------------------


class TestBraceHandling:
    """Opening/closing braces must not appear in config items."""

    def test_open_brace_not_in_items(self) -> None:
        config = "interfaces {\n    ge-0/0/0 {\n        description \"LAN\";\n    }\n}\n"
        result = parse_juniper(config)
        iface = result.get_section("interfaces")
        assert iface is not None
        for item in iface.items:
            assert "{" not in item.key
            assert "}" not in item.key

    def test_close_brace_not_in_items(self) -> None:
        config = "system {\n    host-name R1;\n}\n"
        result = parse_juniper(config)
        system = result.get_section("system")
        assert system is not None
        for item in system.items:
            assert "}" not in item.key


# ---------------------------------------------------------------------------
# Raw config preservation
# ---------------------------------------------------------------------------


class TestRawConfigPreservation:
    """The original text must be stored verbatim for traceability."""

    def test_raw_config_stored(self) -> None:
        config = "system {\n    host-name R1;\n}\n"
        result = parse_juniper(config)
        assert result.raw_config == config

    def test_raw_config_stored_for_fixture(self) -> None:
        raw = _load_fixture()
        result = parse_juniper(raw)
        assert result.raw_config == raw


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Parser must not crash on edge-case inputs."""

    def test_empty_config(self) -> None:
        result = parse_juniper("")
        assert result.vendor == "juniper"
        assert result.hostname is None
        assert result.global_items == []
        assert result.sections == []

    def test_only_comments_and_blanks(self) -> None:
        config = "## comment\n\n# another comment\n\n"
        result = parse_juniper(config)
        assert result.global_items == []
        assert result.sections == []

    def test_malformed_extra_close_brace(self) -> None:
        """A stray closing brace must not raise an exception."""
        config = "system {\n    host-name R1;\n}\n}\n"
        result = parse_juniper(config)
        assert isinstance(result, NormalizedConfig)

    def test_truncated_open_block(self) -> None:
        """Config that ends mid-block (EOF before closing brace) is handled."""
        config = "system {\n    host-name R1;\n"
        result = parse_juniper(config)
        assert result.hostname == "R1"
        assert len(result.sections) == 1  # flushed at EOF

    def test_empty_block(self) -> None:
        config = "routing-options {\n}\n"
        result = parse_juniper(config)
        section = result.get_section("routing-options")
        assert section is not None
        assert section.items == []

    def test_multiple_top_level_sections(self) -> None:
        config = (
            "system {\n    host-name R1;\n}\n"
            "interfaces {\n    ge-0/0/0 { description \"WAN\"; }\n}\n"
            "routing-options {\n    router-id 10.0.0.1;\n}\n"
        )
        result = parse_juniper(config)
        section_names = [s.name.lower() for s in result.sections]
        assert "system" in section_names
        assert "interfaces" in section_names
        assert "routing-options" in section_names
