"""Core domain models for the bid compliance verification platform."""

try:
    from src.compliance.models import ComplianceResult, ComplianceStatus
    from src.evidence.models import Evidence
    from src.requirements.models import Operator, Requirement, RequirementCategory
except ImportError:
    from compliance.models import ComplianceResult, ComplianceStatus
    from evidence.models import Evidence
    from requirements.models import Operator, Requirement, RequirementCategory

__all__ = [
    "Requirement",
    "RequirementCategory",
    "Operator",
    "Evidence",
    "ComplianceResult",
    "ComplianceStatus",
]
