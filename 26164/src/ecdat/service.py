"""
Service layer for ECDAT scanning.

Separates business logic from the FastAPI transport layer.
"""
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
import os

from pydantic import BaseModel

from ecdat.scanner import Scanner
from ecdat.risk import classify_assets

SCANNER_VERSION = "0.1.0"

# ── Custom exceptions ─────────────────────────────────────────────────────────

class ScannerError(Exception):
    """Raised when the Scanner layer fails unrecoverably."""

class AnalysisError(Exception):
    """Raised when the risk-classification layer fails unrecoverably."""


# ── Pydantic response models (P1.2) ───────────────────────────────────────────

class PQCRecommendationOut(BaseModel):
    target_algorithm: str
    nist_standard: str
    migration_type: str


class RiskOut(BaseModel):
    severity: str
    reason: str
    confidence: float
    quantum_threat: str
    pqc_recommendation: Optional[PQCRecommendationOut] = None


class FileLocationOut(BaseModel):
    file_path: str
    line_number: int


class EvidenceOut(BaseModel):
    file_path: str
    line_number: int
    code_snippet: str
    detection_mechanism: str
    matched_rule_id: str


class FindingOut(BaseModel):
    finding_id: str
    algorithm: str
    category: str
    file_location: FileLocationOut
    evidence: EvidenceOut
    risk: RiskOut
    key_length: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None


class ScanSummaryOut(BaseModel):
    total_files_discovered: int
    total_files_scanned: int
    files_skipped: int
    files_failed: int
    total_crypto_assets: int
    severity_counts: Dict[str, int]
    quantum_threat_counts: Dict[str, int]
    algorithm_distribution: Dict[str, int]
    quantum_vulnerable_assets: int


class ScanMetadataOut(BaseModel):
    scan_duration_ms: int
    scanner_version: str


class ScanResponse(BaseModel):
    summary: ScanSummaryOut
    findings: List[FindingOut]
    errors: List[Dict[str, str]]
    skipped_files: List[Dict[str, str]]
    metadata: ScanMetadataOut


# ── Service ───────────────────────────────────────────────────────────────────

class ScanService:
    def __init__(self, max_file_size_bytes: int = 10 * 1024 * 1024):
        self.max_file_size_bytes = max_file_size_bytes

    def run_scan(
        self,
        target_path: str,
        language_filters: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run a full scan and return a JSON-serialisable dict matching ScanResponse."""

        if not os.path.exists(target_path):
            raise ValueError(f"Target path does not exist: {target_path}")

        start_time = time.time()

        # ── Phase 1: discover + scan ──────────────────────────────────────────
        try:
            scanner = Scanner(max_file_size_bytes=self.max_file_size_bytes)
            target = Path(target_path)
            effective_root = target if target.is_dir() else target.parent

            all_files = scanner.discover_files(target_path)
            files = scanner.discover_files(target_path, language_filters=language_filters)
            total_files = len(files)

            assets = []
            for file_path in files:
                assets.extend(scanner.scan_file(file_path, root_dir=effective_root))
        except Exception as e:
            raise ScannerError(f"Scanner encountered an internal failure: {str(e)}") from e

        # ── Phase 2: classify ─────────────────────────────────────────────────
        try:
            assessments = classify_assets(assets)
        except Exception as e:
            raise AnalysisError(f"Analysis encountered an internal failure: {str(e)}") from e

        assessments_by_id = {a.asset_id: a for a in assessments}

        # ── Phase 3: build response ───────────────────────────────────────────
        findings: List[Dict[str, Any]] = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        quantum_threat_counts = {"shor": 0, "grover": 0, "none": 0}
        algorithm_distribution: Dict[str, int] = {}

        for asset in assets:
            assessment = assessments_by_id.get(asset.asset_id)

            if assessment:
                sev = assessment.severity.value
                qt = assessment.quantum_threat.value
                rec = assessment.pqc_recommendation
                reason = assessment.reason
                confidence = assessment.confidence
            else:
                sev = "medium"
                qt = "none"
                rec = None
                reason = "Unknown algorithm mapped to default risk."
                confidence = 0.5

            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            quantum_threat_counts[qt] = quantum_threat_counts.get(qt, 0) + 1
            algorithm_distribution[asset.algorithm] = algorithm_distribution.get(asset.algorithm, 0) + 1

            ev = asset.evidence
            finding: Dict[str, Any] = {
                "finding_id": asset.asset_id,
                "algorithm": asset.algorithm,
                "category": asset.category,
                "key_length": asset.key_length,
                "mode": asset.mode,
                "padding": asset.padding,
                "file_location": {
                    "file_path": str(asset.file_path).replace("\\", "/"),
                    "line_number": asset.line_number,
                },
                "evidence": {
                    "file_path": str(ev.file_path).replace("\\", "/") if ev else str(asset.file_path).replace("\\", "/"),
                    "line_number": ev.line_number if ev else asset.line_number,
                    "code_snippet": ev.code_snippet if ev else "",
                    "detection_mechanism": ev.detection_mechanism if ev else "unknown",
                    "matched_rule_id": ev.matched_rule_id if ev else "unknown",
                },
                "risk": {
                    "severity": sev,
                    "reason": reason,
                    "confidence": confidence,
                    "quantum_threat": qt,
                    "pqc_recommendation": {
                        "target_algorithm": rec.target_algorithm,
                        "nist_standard": rec.nist_standard,
                        "migration_type": rec.migration_type,
                    } if rec else None,
                },
            }
            findings.append(finding)

        duration_ms = int((time.time() - start_time) * 1000)

        return {
            "summary": {
                "total_files_discovered": len(all_files),
                "total_files_scanned": total_files,
                "files_skipped": len(scanner.skipped_files),
                "files_failed": len(scanner.errors),
                "total_crypto_assets": len(assets),
                "severity_counts": severity_counts,
                "quantum_threat_counts": quantum_threat_counts,
                "algorithm_distribution": algorithm_distribution,
                "quantum_vulnerable_assets": (
                    quantum_threat_counts.get("shor", 0)
                    + quantum_threat_counts.get("grover", 0)
                ),
            },
            "findings": findings,
            "errors": scanner.errors,
            "skipped_files": scanner.skipped_files,
            "metadata": {
                "scan_duration_ms": duration_ms,
                "scanner_version": SCANNER_VERSION,
            },
        }
