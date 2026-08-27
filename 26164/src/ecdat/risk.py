"""Deterministic risk classification for discovered cryptographic assets."""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable, List, Optional

from ecdat.models import CryptoAsset


RSA_MINIMUM_KEY_LENGTH = 2048


class RiskSeverity(str, Enum):
    """Risk levels assigned from evidence already present on a CryptoAsset."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class QuantumThreat(str, Enum):
    """Specific quantum computing threat type."""
    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"


@dataclass(frozen=True)
class PQCRecommendation:
    """Structured Post-Quantum Cryptography migration recommendation."""
    target_algorithm: str
    nist_standard: str
    migration_type: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessment:
    """Structured, secret-free interpretation of one cryptographic asset."""
    asset_id: str
    severity: RiskSeverity
    reason: str
    confidence: float
    quantum_threat: QuantumThreat
    pqc_recommendation: Optional[PQCRecommendation] = None

    def to_dict(self) -> dict:
        """Return a serialization-friendly representation."""
        result = asdict(self)
        result["severity"] = self.severity.value
        result["quantum_threat"] = self.quantum_threat.value
        if self.pqc_recommendation:
            result["pqc_recommendation"] = self.pqc_recommendation.to_dict()
        return result


def _assessment(
    asset_id: str,
    severity: RiskSeverity,
    reason: str,
    confidence: float,
    quantum_threat: QuantumThreat = QuantumThreat.NONE,
    pqc_recommendation: Optional[PQCRecommendation] = None,
) -> RiskAssessment:
    return RiskAssessment(
        asset_id=asset_id,
        severity=severity,
        reason=reason,
        confidence=max(0.0, min(round(confidence, 2), 1.0)),
        quantum_threat=quantum_threat,
        pqc_recommendation=pqc_recommendation,
    )


def classify_asset(asset: CryptoAsset) -> RiskAssessment:
    """Classify *asset* using only its structured metadata.

    The rules intentionally do not inspect ``code_snippet`` or raw evidence.
    Missing parameters lower classification confidence and produce MEDIUM
    risk when they prevent a conclusive configuration assessment.
    """
    algorithm = asset.algorithm.strip().upper()
    category = asset.category.strip().lower()
    confidence = asset.confidence
    aid = asset.asset_id

    if category == "hardcoded_secret" or algorithm == "SECRET":
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.CRITICAL,
            reason="A hardcoded secret was detected in source code.",
            confidence=confidence,
            quantum_threat=QuantumThreat.NONE,
        )

    if algorithm in {"MD5", "SHA-1", "SHA1"}:
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.HIGH,
            reason=f"{asset.algorithm} is a legacy or cryptographically weak hashing primitive.",
            confidence=confidence,
            quantum_threat=QuantumThreat.NONE,
            pqc_recommendation=PQCRecommendation("SHA-256 / SHA-3-256", "FIPS 180-4 / FIPS 202", "Direct Replacement")
        )

    if algorithm in {"DES", "3DES", "TRIPLE-DES", "RC4"}:
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.HIGH,
            reason=f"{asset.algorithm} is a deprecated legacy symmetric primitive.",
            confidence=confidence,
            quantum_threat=QuantumThreat.NONE,
            pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Direct Replacement")
        )

    if algorithm in {"RSA", "ECC", "EC", "DSA", "DH", "ECDSA", "ECDH"}:
        rec = None
        if algorithm == "RSA":
            if category == "digital_signature":
                rec = PQCRecommendation("ML-DSA-65", "FIPS 204", "Direct Replacement")
            elif category in {"asymmetric_encryption", "key_exchange"}:
                rec = PQCRecommendation("ML-KEM-768", "FIPS 203", "Hybrid (ECDH + ML-KEM) or Direct Replacement")
            else:
                rec = PQCRecommendation("ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signature)", "FIPS 203 / FIPS 204", "Algorithm Replacement")
        elif algorithm in {"ECDSA", "DSA"}:
            rec = PQCRecommendation("ML-DSA-65", "FIPS 204", "Direct Replacement")
        elif algorithm in {"ECDH", "DH"}:
            rec = PQCRecommendation("ML-KEM-768", "FIPS 203", "Hybrid or Direct Replacement")
        else: # ECC, EC
            rec = PQCRecommendation("ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signature)", "FIPS 203 / FIPS 204", "Algorithm Replacement")

        if algorithm == "RSA" and asset.key_length is not None and asset.key_length < RSA_MINIMUM_KEY_LENGTH:
            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.CRITICAL,
                reason=f"RSA key length {asset.key_length} is below the {RSA_MINIMUM_KEY_LENGTH} bit minimum and is vulnerable to Shor's algorithm.",
                confidence=confidence,
                quantum_threat=QuantumThreat.SHOR,
                pqc_recommendation=rec
            )
        if algorithm == "RSA" and asset.key_length is None:
            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.CRITICAL,
                reason="RSA was detected, but its key length is unavailable; asymmetric cryptography requires migration planning.",
                confidence=min(confidence, 0.75),
                quantum_threat=QuantumThreat.SHOR,
                pqc_recommendation=rec
            )
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.CRITICAL,
            reason=f"{asset.algorithm} is an asymmetric primitive vulnerable to Shor's algorithm.",
            confidence=confidence,
            quantum_threat=QuantumThreat.SHOR,
            pqc_recommendation=rec
        )

    if algorithm == "AES":
        if asset.key_length is not None and asset.key_length < 128:
            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.HIGH,
                reason=f"AES key length {asset.key_length} is below the 128 bit minimum.",
                confidence=confidence,
                quantum_threat=QuantumThreat.NONE,
                pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Upgrade key size and mode")
            )
        if asset.key_length in {128, 192}:
            if asset.mode is None:
                return _assessment(
                    asset_id=aid,
                    severity=RiskSeverity.MEDIUM,
                    reason=f"AES-{asset.key_length} was detected but mode is unavailable. It also provides a reduced post-quantum security margin (approx {asset.key_length // 2} bits) due to Grover's algorithm, falling below the 128-bit safe floor.",
                    confidence=min(confidence, 0.75),
                    quantum_threat=QuantumThreat.GROVER,
                    pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Verify mode and upgrade key size")
                )

            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.MEDIUM,
                reason=f"AES-{asset.key_length} provides a reduced post-quantum security margin (approx {asset.key_length // 2} bits) due to Grover's algorithm, falling below the 128-bit safe floor.",
                confidence=confidence,
                quantum_threat=QuantumThreat.GROVER,
                pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Upgrade key size")
            )

        if asset.key_length is None or asset.mode is None:
            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.MEDIUM,
                reason="AES was detected but key length or mode is unavailable, so configuration strength cannot be confirmed.",
                confidence=min(confidence, 0.75),
                quantum_threat=QuantumThreat.GROVER,
                pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Verify key length and mode")
            )
        if asset.mode.upper() in {"ECB", "CBC"}:
            return _assessment(
                asset_id=aid,
                severity=RiskSeverity.MEDIUM,
                reason=f"AES uses {asset.mode.upper()}, which does not by itself provide authenticated encryption.",
                confidence=confidence,
                quantum_threat=QuantumThreat.NONE,
                pqc_recommendation=PQCRecommendation("AES-256-GCM", "FIPS 197", "Upgrade to authenticated mode")
            )
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.LOW,
            reason="AES has a strong key length and a recognized modern configuration.",
            confidence=confidence,
            quantum_threat=QuantumThreat.NONE,
        )

    if algorithm in {"SHA-256", "SHA256", "SHA-512", "SHA512", "SHA-3", "SHA3"}:
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.INFO,
            reason=f"{asset.algorithm} is a modern approved hashing primitive.",
            confidence=confidence,
            quantum_threat=QuantumThreat.NONE,
        )

    if algorithm in {"CERTIFICATE", "CERT"} or category == "certificate_or_key":
        return _assessment(
            asset_id=aid,
            severity=RiskSeverity.MEDIUM,
            reason="A certificate or key was detected, but its cryptographic parameters are unavailable.",
            confidence=min(confidence, 0.75),
            quantum_threat=QuantumThreat.NONE,
        )

    return _assessment(
        asset_id=aid,
        severity=RiskSeverity.MEDIUM,
        reason=f"The strength of {asset.algorithm} cannot be established from the available metadata.",
        confidence=min(confidence, 0.75),
        quantum_threat=QuantumThreat.NONE,
    )


def classify_assets(assets: Iterable[CryptoAsset]) -> List[RiskAssessment]:
    """Classify assets in input order without changing the assets."""
    return [classify_asset(asset) for asset in assets]