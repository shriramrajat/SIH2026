"""Synthetic realistic tender requirements and bidder evidence fixtures for PS 26100.

All data is strictly synthetic and does not contain real company details, credentials,
or sensitive information.
"""

from typing import List, Tuple
from src.compliance.models import ComplianceStatus
from src.evidence.models import Evidence
from src.requirements.models import Operator, Requirement, RequirementCategory


def get_synthetic_tender_requirements() -> List[Requirement]:
    """Return a representative synthetic suite of tender requirements."""
    return [
        # 1. Numeric Pass: RAM >= 16 GB
        Requirement(
            requirement_id="REQ-001",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="The server system must have a minimum of 16 GB DDR4 RAM installed.",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=12,
            extraction_confidence=0.98,
        ),
        # 2. Numeric Fail: RAM >= 16 GB (tested against insufficient evidence)
        Requirement(
            requirement_id="REQ-002",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="Each workstation must provide at least 16 GB memory.",
            parameter="ram",
            operator=Operator.GTE,
            required_value=16,
            unit="GB",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=12,
            extraction_confidence=0.97,
        ),
        # 3. Numeric Unit Conversion Pass: SSD >= 1 TB
        Requirement(
            requirement_id="REQ-003",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="Storage capacity shall be 1 TB NVMe SSD or higher.",
            parameter="storage",
            operator=Operator.GTE,
            required_value=1,
            unit="TB",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=13,
            extraction_confidence=0.95,
        ),
        # 4. Numeric Upper-Bound Pass: Response Time <= 4 hours
        Requirement(
            requirement_id="REQ-004",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="Maximum on-site incident response time must not exceed 4 hours.",
            parameter="response_time",
            operator=Operator.LTE,
            required_value=4,
            unit="hours",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=18,
            extraction_confidence=0.96,
        ),
        # 5. Numeric Upper-Bound Fail: Response Time <= 4 hours
        Requirement(
            requirement_id="REQ-005",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="Critical SLA resolution time must be within 4 hours.",
            parameter="sla_resolution",
            operator=Operator.LTE,
            required_value=4,
            unit="hours",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=19,
            extraction_confidence=0.96,
        ),
        # 6. Categorical Match: Make in India Class 1
        Requirement(
            requirement_id="REQ-006",
            category=RequirementCategory.ELIGIBILITY,
            original_text="Bidder must be a Class 1 Local Supplier under Make in India policy.",
            parameter="mii_classification",
            operator=Operator.EQUALS,
            required_value="Class 1",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=5,
            extraction_confidence=0.99,
        ),
        # 7. Categorical Mismatch: OS == Ubuntu 22.04 LTS
        Requirement(
            requirement_id="REQ-007",
            category=RequirementCategory.TECHNICAL_SPECIFICATION,
            original_text="Preloaded operating system must be Ubuntu 22.04 LTS.",
            parameter="operating_system",
            operator=Operator.EQUALS,
            required_value="Ubuntu 22.04 LTS",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=14,
            extraction_confidence=0.94,
        ),
        # 8. Document Present: ISO 9001:2015 Certificate
        Requirement(
            requirement_id="REQ-008",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="Bidder must submit a valid ISO 9001:2015 Quality Management Certificate.",
            parameter="iso_9001_certificate",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="ISO 9001:2015 Certificate",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=7,
            extraction_confidence=0.99,
        ),
        # 9. Document Contradictory / Revoked: ISO 27001
        Requirement(
            requirement_id="REQ-009",
            category=RequirementCategory.MANDATORY_DOCUMENT,
            original_text="Bidder must provide an active ISO 27001 Information Security Certificate.",
            parameter="iso_27001_certificate",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="ISO 27001 Certificate",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=8,
            extraction_confidence=0.97,
        ),
        # 10. Missing Evidence: 3 Years Relevant Experience
        Requirement(
            requirement_id="REQ-010",
            category=RequirementCategory.EXPERIENCE,
            original_text="Bidder must possess at least 3 years of experience in enterprise hardware supply.",
            parameter="relevant_experience",
            operator=Operator.GTE,
            required_value=3,
            unit="years",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=6,
            extraction_confidence=0.95,
        ),
        # 11. Partial Evidence: 3 Client References
        Requirement(
            requirement_id="REQ-011",
            category=RequirementCategory.EXPERIENCE,
            original_text="Bidder must attach 3 satisfied client reference letters for past installations.",
            parameter="client_references",
            operator=Operator.DOCUMENT_REQUIRED,
            required_value="3 Reference Letters",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=9,
            extraction_confidence=0.92,
        ),
        # 12. Ambiguous Evidence: Annual Turnover >= 50 Lakhs
        Requirement(
            requirement_id="REQ-012",
            category=RequirementCategory.FINANCIAL,
            original_text="Average annual turnover for past 3 fiscal years must be at least 50 Lakhs INR.",
            parameter="annual_turnover",
            operator=Operator.GTE,
            required_value=50,
            unit="Lakhs",
            mandatory=True,
            source_document="tender_gem_server_2026.pdf",
            page=10,
            extraction_confidence=0.96,
        ),
    ]


def get_synthetic_bidder_evidence() -> List[Evidence]:
    """Return synthetic bidder evidence matching the synthetic requirements."""
    return [
        # EVID-001 for REQ-001 (RAM >= 16 GB -> 32 GB) -> COMPLIANT
        Evidence(
            evidence_id="EVID-001",
            requirement_id="REQ-001",
            document_id="bidder_datasheet_alpha.pdf",
            page=4,
            section="Memory Specifications",
            text="System Memory: 32 GB DDR4-3200 ECC Registered RDIMM installed.",
            extracted_value=32,
            unit="GB",
            confidence=0.98,
        ),
        # EVID-002 for REQ-002 (RAM >= 16 GB -> 8 GB) -> NON_COMPLIANT
        Evidence(
            evidence_id="EVID-002",
            requirement_id="REQ-002",
            document_id="bidder_workstation_specs.pdf",
            page=2,
            section="Base Configuration",
            text="Memory installed: 8 GB DDR4 Non-ECC memory.",
            extracted_value=8,
            unit="GB",
            confidence=0.99,
        ),
        # EVID-003 for REQ-003 (SSD >= 1 TB -> 2048 GB) -> COMPLIANT (conversion)
        Evidence(
            evidence_id="EVID-003",
            requirement_id="REQ-003",
            document_id="bidder_datasheet_alpha.pdf",
            page=5,
            section="Storage Subsystem",
            text="Internal Storage: 2048 GB PCIe Gen4 M.2 NVMe Solid State Drive.",
            extracted_value=2048,
            unit="GB",
            confidence=0.97,
        ),
        # EVID-004 for REQ-004 (Response Time <= 4 hours -> 2 hours) -> COMPLIANT
        Evidence(
            evidence_id="EVID-004",
            requirement_id="REQ-004",
            document_id="bidder_sla_commitment.pdf",
            page=1,
            section="On-site SLA Support",
            text="Guaranteed on-site response time: 2 hours from ticket acknowledgement.",
            extracted_value=2,
            unit="hours",
            confidence=0.95,
        ),
        # EVID-005 for REQ-005 (Response Time <= 4 hours -> 6 hours) -> NON_COMPLIANT
        Evidence(
            evidence_id="EVID-005",
            requirement_id="REQ-005",
            document_id="bidder_sla_commitment.pdf",
            page=2,
            section="Standard SLA Terms",
            text="Standard SLA resolution window: 6 hours.",
            extracted_value=6,
            unit="hours",
            confidence=0.96,
        ),
        # EVID-006 for REQ-006 (Make in India == Class 1 -> Class 1) -> COMPLIANT
        Evidence(
            evidence_id="EVID-006",
            requirement_id="REQ-006",
            document_id="bidder_mii_self_declaration.pdf",
            page=1,
            section="Local Content Declaration",
            text="We hereby certify that the offered product qualifies as Class 1 Local Supplier.",
            extracted_value="Class 1",
            confidence=0.99,
        ),
        # EVID-007 for REQ-007 (OS == Ubuntu -> Windows 11 Home) -> NON_COMPLIANT
        Evidence(
            evidence_id="EVID-007",
            requirement_id="REQ-007",
            document_id="bidder_datasheet_alpha.pdf",
            page=7,
            section="Software & OS",
            text="Factory pre-installed OS: Windows 11 Home 64-bit.",
            extracted_value="Windows 11 Home",
            confidence=0.98,
        ),
        # EVID-008 for REQ-008 (ISO 9001 Certificate Present) -> COMPLIANT
        Evidence(
            evidence_id="EVID-008",
            requirement_id="REQ-008",
            document_id="iso_9001_certificate_valid.pdf",
            page=1,
            section="Certificate of Registration",
            text="Certificate No: QMS-2024-9988 valid through December 2027 for ISO 9001:2015 standards.",
            extracted_value="ISO 9001:2015 Valid Certificate",
            confidence=0.99,
        ),
        # EVID-009 for REQ-009 (ISO 27001 Expired/Contradictory) -> NON_COMPLIANT
        Evidence(
            evidence_id="EVID-009",
            requirement_id="REQ-009",
            document_id="iso_27001_notice.pdf",
            page=1,
            section="Audit Notice",
            text="ISO 27001 certificate expired on 2024-01-15; renewal audit pending.",
            extracted_value="Expired Certificate",
            confidence=0.95,
            is_contradictory=True,
        ),
        # NOTE: No evidence provided for REQ-010 -> Expected: NEEDS_REVIEW
        # EVID-011 for REQ-011 (Partial reference submission) -> PARTIALLY_COMPLIANT
        Evidence(
            evidence_id="EVID-011",
            requirement_id="REQ-011",
            document_id="client_feedback_bundle.pdf",
            page=1,
            section="Client References",
            text="Submitting 1 client completion certificate from PSU Alpha. Remaining 2 references pending.",
            extracted_value="1 Reference Letter",
            confidence=0.90,
            is_partial=True,
        ),
        # EVID-012 for REQ-012 (Ambiguous turnover submission) -> NEEDS_REVIEW
        Evidence(
            evidence_id="EVID-012",
            requirement_id="REQ-012",
            document_id="internal_draft_accounts.pdf",
            page=3,
            section="Provisional Figures",
            text="Internal unaudited draft statement shows approximate revenue 50 without CA seal.",
            extracted_value=None,
            confidence=0.40,
            is_ambiguous=True,
        ),
    ]


def get_expected_synthetic_outcomes() -> List[Tuple[str, ComplianceStatus]]:
    """Return expected compliance statuses for all synthetic requirements."""
    return [
        ("REQ-001", ComplianceStatus.COMPLIANT),
        ("REQ-002", ComplianceStatus.NON_COMPLIANT),
        ("REQ-003", ComplianceStatus.COMPLIANT),
        ("REQ-004", ComplianceStatus.COMPLIANT),
        ("REQ-005", ComplianceStatus.NON_COMPLIANT),
        ("REQ-006", ComplianceStatus.COMPLIANT),
        ("REQ-007", ComplianceStatus.NON_COMPLIANT),
        ("REQ-008", ComplianceStatus.COMPLIANT),
        ("REQ-009", ComplianceStatus.NON_COMPLIANT),
        ("REQ-010", ComplianceStatus.NEEDS_REVIEW),
        ("REQ-011", ComplianceStatus.PARTIALLY_COMPLIANT),
        ("REQ-012", ComplianceStatus.NEEDS_REVIEW),
    ]
