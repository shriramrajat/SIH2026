"""Domain models for bidder-submitted evidence."""

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    """Structured evidence record extracted from bidder submission documents."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    evidence_id: str = Field(
        ...,
        description="Unique identifier for the evidence item (e.g., EVID-001)",
    )
    requirement_id: Optional[str] = Field(
        default=None,
        description="ID of the requirement this evidence targets",
    )
    document_id: Optional[str] = Field(
        default=None,
        description="Bidder submission document filename or ID",
    )
    page: Optional[int] = Field(
        default=None,
        description="Page number in bidder document where evidence appears",
    )
    section: Optional[str] = Field(
        default=None,
        description="Document section or header containing the evidence",
    )
    text: str = Field(
        ...,
        description="Verbatim excerpt or statement from the bidder document",
    )
    extracted_value: Optional[Any] = Field(
        default=None,
        description="Structured/normalized value extracted from the evidence text",
    )
    unit: Optional[str] = Field(
        default=None,
        description="Measurement unit associated with extracted value (e.g., GB, years)",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score of evidence extraction",
    )
    is_contradictory: bool = Field(
        default=False,
        description="Explicit flag indicating the evidence contradicts or fails the requirement",
    )
    is_partial: bool = Field(
        default=False,
        description="Explicit flag indicating the evidence only partially addresses the requirement",
    )
    is_ambiguous: bool = Field(
        default=False,
        description="Explicit flag indicating the evidence is unverified or ambiguous",
    )
