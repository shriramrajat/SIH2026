from typing import Literal


Vendor = Literal["cisco", "juniper", "unknown"]


def detect_vendor(config: str) -> Vendor:
    """Detect the vendor from configuration content."""

    lines = config.splitlines()

    for line in lines:
        normalized = line.strip().lower()

        # Cisco markers
        if normalized.startswith("version ") and normalized[8:].strip():
            return "cisco"
        if normalized.startswith("hostname "):
            return "cisco"
        if normalized.startswith("enable secret "):
            return "cisco"
        if normalized.startswith("ip ssh version "):
            return "cisco"

        # Juniper markers
        if normalized.startswith("system {"):
            return "juniper"
        if normalized.startswith("host-name ") and normalized.endswith(";"):
            return "juniper"
        if normalized.startswith("authentication-order"):
            return "juniper"
        if normalized.startswith("root-authentication"):
            return "juniper"
        if normalized.startswith("interfaces {"):
            return "juniper"

    return "unknown"