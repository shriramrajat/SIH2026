"""
tests/unit/test_cisco_parser.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the Cisco IOS foundation parser
(:func:`src.parsers.cisco.parse_cisco`).
"""

from pathlib import Path

from src.parsers.cisco import parse_cisco
from src.normalization.model import NormalizedConfig, ConfigSection, ConfigItem


FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "cisco-basic.conf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------


class TestParseCiscoReturnType:
    """The parser always returns a :class:`NormalizedConfig` object."""

    def test_returns_normalized_config(self) -> None:
        result = parse_cisco("hostname LAB-ROUTER\n")
        assert isinstance(result, NormalizedConfig)

    def test_vendor_is_cisco(self) -> None:
        result = parse_cisco("hostname LAB-ROUTER\n")
        assert result.vendor == "cisco"


# ---------------------------------------------------------------------------
# Hostname extraction
# ---------------------------------------------------------------------------


class TestHostnameExtraction:
    """Tests for hostname identification within Cisco configurations."""

    def test_extracts_hostname(self) -> None:
        config = "version 17.9\nhostname LAB-ROUTER-01\n"
        result = parse_cisco(config)
        assert result.hostname == "LAB-ROUTER-01"

    def test_hostname_is_none_when_absent(self) -> None:
        config = "version 17.9\nip ssh version 2\n"
        result = parse_cisco(config)
        assert result.hostname is None

    def test_extracts_hostname_from_fixture(self) -> None:
        result = parse_cisco(_load_fixture())
        assert result.hostname == "LAB-ROUTER-01"


# ---------------------------------------------------------------------------
# Global directives
# ---------------------------------------------------------------------------


class TestGlobalItems:
    """Tests for top-level (non-section) configuration directives."""

    def test_global_items_is_list(self) -> None:
        result = parse_cisco("ip ssh version 2\n")
        assert isinstance(result.global_items, list)

    def test_version_line_appears_in_global_items(self) -> None:
        config = "version 17.9\nhostname LAB-ROUTER-01\n"
        result = parse_cisco(config)
        keys = [item.key.lower() for item in result.global_items]
        assert "version" in keys

    def test_get_global_helper_finds_item(self) -> None:
        config = "ip ssh version 2\n"
        result = parse_cisco(config)
        # "ip" is the directive key for this style of top-level command
        item = result.get_global("ip")
        assert item is not None

    def test_get_global_helper_returns_none_for_absent_key(self) -> None:
        result = parse_cisco("hostname LAB-ROUTER\n")
        assert result.get_global("nonexistent-directive") is None


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------


class TestSectionParsing:
    """Tests for block-section boundary detection."""

    def test_sections_is_list(self) -> None:
        result = parse_cisco("hostname LAB-ROUTER\n")
        assert isinstance(result.sections, list)

    def test_line_vty_becomes_section(self) -> None:
        config = (
            "hostname LAB-ROUTER\n"
            "!\n"
            "line vty 0 4\n"
            " transport input ssh\n"
            " login local\n"
            "!\n"
        )
        result = parse_cisco(config)
        section_names = [s.name.lower() for s in result.sections]
        assert any("line vty" in name for name in section_names)

    def test_section_items_captured(self) -> None:
        config = (
            "line vty 0 4\n"
            " transport input ssh\n"
            " login local\n"
            "!\n"
        )
        result = parse_cisco(config)
        assert len(result.sections) == 1
        section = result.sections[0]
        item_keys = [item.key.lower() for item in section.items]
        assert "transport" in item_keys

    def test_fixture_contains_sections(self) -> None:
        result = parse_cisco(_load_fixture())
        assert len(result.sections) > 0

    def test_get_section_helper(self) -> None:
        config = (
            "line vty 0 4\n"
            " transport input ssh\n"
            "!\n"
        )
        result = parse_cisco(config)
        section = result.get_section("line vty 0 4")
        assert section is not None
        assert isinstance(section, ConfigSection)

    def test_get_section_returns_none_for_absent_section(self) -> None:
        result = parse_cisco("hostname LAB-ROUTER\n")
        assert result.get_section("interface GigabitEthernet0/0") is None


# ---------------------------------------------------------------------------
# Raw config preservation
# ---------------------------------------------------------------------------


class TestRawConfigPreservation:
    """The original text must be stored verbatim for traceability."""

    def test_raw_config_stored(self) -> None:
        config = "version 17.9\nhostname LAB-ROUTER\n"
        result = parse_cisco(config)
        assert result.raw_config == config


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Parser should not crash on edge-case inputs."""

    def test_empty_config(self) -> None:
        result = parse_cisco("")
        assert result.vendor == "cisco"
        assert result.hostname is None
        assert result.global_items == []
        assert result.sections == []

    def test_only_comments_and_blanks(self) -> None:
        config = "!\n!\n\n!\n"
        result = parse_cisco(config)
        assert result.global_items == []
        assert result.sections == []

    def test_end_marker_does_not_appear_as_item(self) -> None:
        config = "hostname LAB-ROUTER\nend\n"
        result = parse_cisco(config)
        keys = [item.key.lower() for item in result.global_items]
        assert "end" not in keys
