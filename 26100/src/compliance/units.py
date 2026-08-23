"""Lightweight unit normalization and conversion for deterministic compliance checks."""

from typing import Optional, Tuple

# Digital storage units normalized to bytes
_STORAGE_MULTIPLIERS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1024,
    "kbyte": 1024,
    "kbytes": 1024,
    "mb": 1024**2,
    "mbyte": 1024**2,
    "mbytes": 1024**2,
    "gb": 1024**3,
    "gbyte": 1024**3,
    "gbytes": 1024**3,
    "tb": 1024**4,
    "tbyte": 1024**4,
    "tbytes": 1024**4,
}

# Time units normalized to hours
_TIME_MULTIPLIERS = {
    "h": 1,
    "hr": 1,
    "hrs": 1,
    "hour": 1,
    "hours": 1,
    "day": 24,
    "days": 24,
    "d": 24,
    "week": 24 * 7,
    "weeks": 24 * 7,
    "month": 24 * 30,
    "months": 24 * 30,
    "yr": 24 * 365,
    "yrs": 24 * 365,
    "year": 24 * 365,
    "years": 24 * 365,
}

# Currency and Indian numbering multiples normalized to base INR
_CURRENCY_MULTIPLIERS = {
    "inr": 1,
    "rs": 1,
    "rupee": 1,
    "rupees": 1,
    "thousand": 1_000,
    "thousands": 1_000,
    "k": 1_000,
    "lakh": 100_000,
    "lakhs": 100_000,
    "lac": 100_000,
    "lacs": 100_000,
    "crore": 10_000_000,
    "crores": 10_000_000,
    "cr": 10_000_000,
    "million": 1_000_000,
    "millions": 1_000_000,
}

# Percentage units
_PERCENT_UNITS = {"%", "percent", "pct", "percentage"}


def normalize_unit_string(unit: Optional[str]) -> Optional[str]:
    """Normalize unit string by lowercasing and trimming punctuation/spaces."""
    if not unit:
        return None
    cleaned = unit.strip().lower().rstrip(".").rstrip(",")
    return cleaned if cleaned else None


def convert_values_to_common_unit(
    req_value: float | int,
    req_unit: Optional[str],
    evidence_value: float | int,
    evidence_unit: Optional[str],
) -> Optional[Tuple[float, float, str]]:
    """Convert requirement and evidence numeric values to a common base unit.

    Returns:
        Tuple of (normalized_req_value, normalized_evidence_value, display_unit)
        or None if units are incompatible or unknown.
    """
    norm_req_unit = normalize_unit_string(req_unit)
    norm_evi_unit = normalize_unit_string(evidence_unit)

    # 1. No units specified for both -> direct numeric comparison
    if not norm_req_unit and not norm_evi_unit:
        return float(req_value), float(evidence_value), ""

    # 2. Identical unit strings -> direct comparison with original unit
    if norm_req_unit == norm_evi_unit:
        display = req_unit.strip() if req_unit else ""
        return float(req_value), float(evidence_value), display

    # 3. One has no unit while other does -> ambiguous unless 0
    if not norm_req_unit or not norm_evi_unit:
        return None

    # 4. Storage units check
    if norm_req_unit in _STORAGE_MULTIPLIERS and norm_evi_unit in _STORAGE_MULTIPLIERS:
        req_base = float(req_value) * _STORAGE_MULTIPLIERS[norm_req_unit]
        evi_base = float(evidence_value) * _STORAGE_MULTIPLIERS[norm_evi_unit]
        # Return in requirement's unit for clear explanation
        req_multiplier = _STORAGE_MULTIPLIERS[norm_req_unit]
        return float(req_value), evi_base / req_multiplier, req_unit.strip()

    # 5. Time units check
    if norm_req_unit in _TIME_MULTIPLIERS and norm_evi_unit in _TIME_MULTIPLIERS:
        req_base = float(req_value) * _TIME_MULTIPLIERS[norm_req_unit]
        evi_base = float(evidence_value) * _TIME_MULTIPLIERS[norm_evi_unit]
        req_multiplier = _TIME_MULTIPLIERS[norm_req_unit]
        return float(req_value), evi_base / req_multiplier, req_unit.strip()

    # 6. Currency/Numbering multiples check
    if norm_req_unit in _CURRENCY_MULTIPLIERS and norm_evi_unit in _CURRENCY_MULTIPLIERS:
        req_base = float(req_value) * _CURRENCY_MULTIPLIERS[norm_req_unit]
        evi_base = float(evidence_value) * _CURRENCY_MULTIPLIERS[norm_evi_unit]
        req_multiplier = _CURRENCY_MULTIPLIERS[norm_req_unit]
        return float(req_value), evi_base / req_multiplier, req_unit.strip()

    # 7. Percentage units check
    if norm_req_unit in _PERCENT_UNITS and norm_evi_unit in _PERCENT_UNITS:
        return float(req_value), float(evidence_value), "%"

    # Incompatible or unknown units
    return None
