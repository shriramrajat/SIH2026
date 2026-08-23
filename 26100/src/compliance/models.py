"""Domain models for compliance evaluation results."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ComplianceStatus(str, Enum):
    """Allowed compliance decision states."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class ComplianceResult(BaseModel):
    """Traceable, evidence-backed evaluation result for a tender requirement."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    requirement_id: str = Field(
        ...,
        description="ID of the requirement evaluated",
    )
    bidder_id: Optional[str] = Field(
        default=None,
        description="ID or name of the bidder evaluated",
    )
    status: ComplianceStatus = Field(
        ...,
        description="Compliance determination: COMPLIANT, NON_COMPLIANT, PARTIALLY_COMPLIANT, or NEEDS_REVIEW",
    )
    comparison: Optional[str] = Field(
        default=None,
        description="Deterministic comparison expression (e.g., '32.0 GB >= 16.0 GB')",
    )
    explanation: str = Field(
        ...,
        description="Factual, evidence-backed explanation justifying the compliance status",
    )
    confidence: Optional[float] = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score of the compliance determination",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of evidence IDs referenced to reach this decision (provenance)",
    )
