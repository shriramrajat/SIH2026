"""Compliance evaluation module."""

try:
    from src.compliance.engine import ComplianceEngine, evaluate_bid, evaluate_requirement
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.compliance.units import convert_values_to_common_unit, normalize_unit_string
except ImportError:
    from .engine import ComplianceEngine, evaluate_bid, evaluate_requirement
    from .models import ComplianceResult, ComplianceStatus
    from .units import convert_values_to_common_unit, normalize_unit_string

__all__ = [
    "ComplianceEngine",
    "evaluate_requirement",
    "evaluate_bid",
    "ComplianceResult",
    "ComplianceStatus",
    "convert_values_to_common_unit",
    "normalize_unit_string",
]
