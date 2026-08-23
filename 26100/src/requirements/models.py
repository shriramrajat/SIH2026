"""Domain models for structured tender requirements."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class RequirementCategory(str, Enum):
    """Broad classification of procurement requirements."""

    ELIGIBILITY = "eligibility"
    TECHNICAL_SPECIFICATION = "technical_specification"
    MANDATORY_DOCUMENT = "mandatory_document"
    FINANCIAL = "financial"
    EXPERIENCE = "experience"
    QUANTITY = "quantity"
    OTHER = "other"


class Operator(str, Enum):
    """Supported deterministic evaluation operators."""

    # Numeric comparisons
    GTE = ">="
    LTE = "<="
    GT = ">"
    LT = "<"
    EQ = "="
    EQUALS = "=="
    NEQ = "!="

    # Categorical & string matching
    EXACT = "EXACT"
    CONTAINS = "CONTAINS"

    # Presence & document checks
    DOCUMENT_REQUIRED = "DOCUMENT_REQUIRED"
    EXISTS = "EXISTS"
    PRESENT = "PRESENT"


class Requirement(BaseModel):
    """Structured tender requirement record."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    requirement_id: str = Field(
        ...,
        description="Unique identifier for the requirement (e.g., REQ-001)",
    )
    category: RequirementCategory | str = Field(
        default=RequirementCategory.TECHNICAL_SPECIFICATION,
        description="Requirement category (technical, financial, document, etc.)",
    )
    original_text: str = Field(
        ...,
        description="Verbatim requirement clause extracted from the tender document",
    )
    parameter: Optional[str] = Field(
        default=None,
        description="Normalized parameter name (e.g., ram, turnover, iso_9001)",
    )
    operator: Optional[Operator | str] = Field(
        default=None,
        description="Evaluation operator (e.g., >=, <=, ==, DOCUMENT_REQUIRED)",
    )
    required_value: Optional[Any] = Field(
        default=None,
        description="Threshold, target value, or required state",
    )
    unit: Optional[str] = Field(
        default=None,
        description="Measurement unit if applicable (e.g., GB, years, INR, Lakhs)",
    )
    mandatory: bool = Field(
        default=True,
        description="Whether meeting this requirement is mandatory for bid qualification",
    )
    source_document: Optional[str] = Field(
        default=None,
        description="Source tender file name or identifier",
    )
    page: Optional[int] = Field(
        default=None,
        description="Page number in source tender where requirement was found",
    )
    extraction_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score of automated requirement extraction (if applicable)",
    )
