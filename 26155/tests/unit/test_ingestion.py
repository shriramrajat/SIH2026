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

    def test_detects_juniper_from_system_block(self) -> None:
        """A ``system {`` block is a reliable Juniper indicator."""
        config = "system {\n    host-name LAB-SRX;\n}\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_hostname(self) -> None:
        """A Junos ``host-name`` directive with semicolon is detected."""
        config = "    host-name LAB-SRX-01;\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_authentication_order(self) -> None:
        """``authentication-order`` is a Junos-specific directive."""
        config = "authentication-order [ radius password ];\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_root_authentication(self) -> None:
        """``root-authentication`` is a Junos-specific directive."""
        config = "root-authentication {\n"
        assert detect_vendor(config) == "juniper"

    def test_detects_juniper_from_interfaces_block(self) -> None:
        """``interfaces {`` is a Junos-specific block."""
        config = "interfaces {\n    ge-0/0/0 {\n"
        assert detect_vendor(config) == "juniper"

    def test_returns_unknown_for_generic_braces(self) -> None:
        """Generic braces without Junos keywords are unknown."""
        config = "custom_block {\n    some_value 123;\n}\n"
        assert detect_vendor(config) == "unknown"
