from typing import Literal


Vendor = Literal["cisco", "unknown"]


def detect_vendor(config: str) -> Vendor:
    """Detect the vendor from configuration content."""

    lines = config.splitlines()

    for line in lines:
        normalized = line.strip().lower()

        if normalized.startswith("version ") and normalized[8:].strip():
            return "cisco"

        if normalized.startswith("hostname "):
            return "cisco"

        if normalized.startswith("enable secret "):
            return "cisco"

        if normalized.startswith("ip ssh version "):
            return "cisco"

    return "unknown"