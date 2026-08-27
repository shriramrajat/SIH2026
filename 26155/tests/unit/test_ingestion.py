"""
tests/unit/test_ingestion.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the ingestion layer:
- loader.py  (load_config)
- detector.py (detect_vendor)
"""

import pytest
from pathlib import Path

from src.ingestion.loader import load_config
from src.ingestion.detector import detect_vendor


# ---------------------------------------------------------------------------
# loader tests
# ---------------------------------------------------------------------------


class TestLoadConfig:
    """Tests for :func:`src.ingestion.loader.load_config`."""

    def test_loads_existing_file(self, tmp_path: Path) -> None:
        """A UTF-8 file is read and its content returned verbatim."""
        config_file = tmp_path / "router.conf"
        config_file.write_text("hostname TEST-ROUTER\n", encoding="utf-8")

        result = load_config(str(config_file))

        assert result == "hostname TEST-ROUTER\n"

    def test_raises_for_missing_file(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when the path does not exist."""
        missing = tmp_path / "does-not-exist.conf"

        with pytest.raises(FileNotFoundError, match="does-not-exist.conf"):
            load_config(str(missing))

    def test_raises_for_directory_path(self, tmp_path: Path) -> None:
        """ValueError is raised when the path points to a directory."""
        with pytest.raises(ValueError, match="not a file"):
            load_config(str(tmp_path))

    def test_returns_unicode_content(self, tmp_path: Path) -> None:
        """Unicode characters in the config file are preserved correctly."""
        config_file = tmp_path / "unicode.conf"
        content = "hostname RÔUTER\n"
        config_file.write_text(content, encoding="utf-8")

        result = load_config(str(config_file))

        assert result == content


# ---------------------------------------------------------------------------
# detector tests
# ---------------------------------------------------------------------------


class TestDetectVendor:
    """Tests for :func:`src.ingestion.detector.detect_vendor`."""

    def test_detects_cisco_from_version_line(self) -> None:
        """A ``version`` header is a reliable Cisco indicator."""
        config = "version 17.9\nhostname LAB-ROUTER\n"
        assert detect_vendor(config) == "cisco"

    def test_detects_cisco_from_hostname(self) -> None:
        """A ``hostname`` directive alone is sufficient for Cisco detection."""
        config = "hostname LAB-ROUTER\n"
        assert detect_vendor(config) == "cisco"

    def test_detects_cisco_from_ip_ssh(self) -> None:
        """``ip ssh version`` is a Cisco-specific directive."""
        config = "ip ssh version 2\n"
        assert detect_vendor(config) == "cisco"

    def test_detects_cisco_fixture(self) -> None:
        """The canonical Cisco fixture file is detected as Cisco."""
        fixture = (
            Path(__file__).parent.parent / "fixtures" / "cisco-basic.conf"
        )
        content = fixture.read_text(encoding="utf-8")
        assert detect_vendor(content) == "cisco"

    def test_returns_unknown_for_unrecognised_config(self) -> None:
        """Content with no recognisable Cisco patterns yields ``'unknown'``."""
        config = "some unknown configuration\nanother unknown command\n"
        assert detect_vendor(config) == "unknown"

    def test_returns_unknown_for_empty_string(self) -> None:
        """An empty string cannot be attributed to any vendor."""
        assert detect_vendor("") == "unknown"


class TestDetectVendorJuniper:
    """Juniper JunOS detection tests for :func:`src.ingestion.detector.detect_vendor`."""

    # ---- Positive: JunOS-specific markers ----------------------------------

    def test_detects_juniper_from_system_block(self) -> None:
        """``system {`` is a JunOS top-level block opener."""
        config = "system {\n    host-name R1;\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_double_hash_comment(self) -> None:
        """A ``## `` file-level header comment is JunOS-specific."""
        config = "## Last commit: 2026-01-01 by admin\nsystem {\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_interfaces_block(self) -> None:
        """``interfaces {`` is a JunOS top-level block not used by Cisco."""
        config = "interfaces {\n    ge-0/0/0 {\n        description \"WAN\";\n    }\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_security_block(self) -> None:
        """``security {`` is a JunOS top-level block."""
        config = "security {\n    zones {\n    }\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_routing_options_block(self) -> None:
        """``routing-options {`` is a JunOS top-level block."""
        config = "routing-options {\n    router-id 10.0.0.1;\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_protocols_block(self) -> None:
        """``protocols {`` is a JunOS top-level block."""
        config = "protocols {\n    ospf {\n    }\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_fixture(self) -> None:
        """The canonical Juniper fixture file is detected as juniper."""
        fixture = (
            Path(__file__).parent.parent / "fixtures" / "juniper-basic.conf"
        )
        content = fixture.read_text(encoding="utf-8")
        assert detect_vendor(content) == "juniper"

    # ---- Negative: Juniper markers must NOT fire on non-Juniper content ----

    def test_system_without_brace_does_not_trigger_juniper(self) -> None:
        """A plain 'system' word without '{' must not trigger Juniper detection."""
        config = "system management\nsome value here\n"
        # No brace → not a JunOS block opener → should be unknown
        assert detect_vendor(config) == "unknown"

    def test_single_hash_comment_does_not_trigger_juniper(self) -> None:
        """A single '#' comment does not constitute a JunOS double-hash marker."""
        config = "# This is some config\nhostname R1\n"
        # Cisco hostname marker triggers first
        assert detect_vendor(config) == "cisco"

    # ---- Ambiguous / mixed-marker behaviour --------------------------------

    def test_cisco_wins_when_cisco_marker_appears_first(self) -> None:
        """When Cisco marker appears before Juniper marker, result is Cisco.

        First-match behaviour must be preserved — whichever vendor's marker
        appears on an earlier line wins.
        """
        config = (
            "version 17.9\n"          # Cisco marker — line 1
            "system {\n"              # Juniper marker — line 2
            "    host-name R1;\n"
            "}\n"
        )
        assert detect_vendor(config) == "cisco"

    def test_juniper_wins_when_only_juniper_markers_present(self) -> None:
        """A pure JunOS config with no Cisco markers detects as juniper."""
        config = (
            "## JunOS config\n"
            "system {\n"
            "    host-name SRX-01;\n"
            "}\n"
        )
        assert detect_vendor(config) == "juniper"

    def test_only_whitespace_returns_unknown(self) -> None:
        """Whitespace-only content is unattributable."""
        assert detect_vendor("   \n   \n") == "unknown"

    def test_structured_non_network_config_returns_unknown(self) -> None:
        """Content with braces but no known markers is not falsely classified."""
        config = "{\n    key value;\n    other setting;\n}\n"
        # Bare '{' is a closing/opening brace without a block name prefix
        # matching our markers — should remain unknown.
        assert detect_vendor(config) == "unknown"

    # ---- Case handling -----------------------------------------------------

    def test_cisco_hostname_case_insensitive(self) -> None:
        """Cisco 'HOSTNAME' in uppercase still detects as Cisco."""
        config = "HOSTNAME LAB-ROUTER\n"
        assert detect_vendor(config) == "cisco"

    def test_cisco_version_case_insensitive(self) -> None:
        """Cisco 'VERSION' in uppercase still detects as Cisco."""
        config = "VERSION 17.9\n"
        assert detect_vendor(config) == "cisco"

    def test_juniper_system_block_case_insensitive(self) -> None:
        """Juniper 'SYSTEM {' in uppercase still detects as Juniper."""
        config = "SYSTEM {\n    host-name R1;\n}\n"
        assert detect_vendor(config) == "juniper"