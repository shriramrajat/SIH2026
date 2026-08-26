"""Deterministic risk classification for discovered cryptographic assets."""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable, List

from ecdat.models import CryptoAsset


RSA_MINIMUM_KEY_LENGTH = 2048


class RiskSeverity(str, Enum):
    """Risk levels assigned from evidence already present on a CryptoAsset."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class RiskAssessment:
    """Structured, secret-free interpretation of one cryptographic asset."""

    severity: RiskSeverity
    reason: str
    recommendation: str
    confidence: float

    def to_dict(self) -> dict:
        """Return a serialization-friendly representation."""
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


def _assessment(
    severity: RiskSeverity,
    reason: str,
    recommendation: str,
    confidence: float,
) -> RiskAssessment:
    return RiskAssessment(
        severity=severity,
        reason=reason,
        recommendation=recommendation,
        confidence=round(confidence, 2),
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

    if category == "hardcoded_secret" or algorithm == "SECRET":
        return _assessment(
            RiskSeverity.CRITICAL,
            "A hardcoded secret was detected in source code.",
            "Remove the literal and load the secret from a managed secret store or runtime configuration.",
            confidence,
        )

    if algorithm in {"MD5", "SHA-1", "SHA1", "DES", "3DES", "TRIPLE-DES", "RC4"}:
        return _assessment(
            RiskSeverity.HIGH,
            f"{asset.algorithm} is a legacy or cryptographically weak primitive.",
            "Replace it with a modern approved primitive such as SHA-256/SHA-3 or AES-GCM.",
            confidence,
        )

    if algorithm in {"RSA", "ECC", "EC", "DSA", "DH", "ECDSA", "ECDH"}:
        if algorithm == "RSA" and asset.key_length is not None and asset.key_length < RSA_MINIMUM_KEY_LENGTH:
            return _assessment(
                RiskSeverity.HIGH,
                f"RSA key length {asset.key_length} is below the {RSA_MINIMUM_KEY_LENGTH} bit minimum.",
                "Regenerate the key with at least 2048 bits and plan migration to a post-quantum design.",
                confidence,
            )
        if algorithm == "RSA" and asset.key_length is None:
            return _assessment(
                RiskSeverity.CRITICAL,
                "RSA was detected, but its key length is unavailable; asymmetric cryptography requires migration planning.",
                "Determine the key size and plan migration to a post-quantum design.",
                min(confidence, 0.75),
            )
        return _assessment(
            RiskSeverity.CRITICAL,
            f"{asset.algorithm} is an asymmetric primitive vulnerable to quantum attacks.",
            "Plan migration to an approved post-quantum algorithm or hybrid design.",
            confidence,
        )

    if algorithm == "AES":
        if asset.key_length is not None and asset.key_length < 128:
            return _assessment(
                RiskSeverity.HIGH,
                f"AES key length {asset.key_length} is below the 128 bit minimum.",
                "Replace the key with at least AES-128, preferably AES-256-GCM.",
                confidence,
            )
        if asset.key_length == 128:
            return _assessment(
                RiskSeverity.MEDIUM,
                "AES-128 provides a reduced post-quantum security margin.",
                "Prefer AES-256 with an authenticated mode such as GCM.",
                confidence,
            )
        if asset.key_length is None or asset.mode is None:
            return _assessment(
                RiskSeverity.MEDIUM,
                "AES was detected but key length or mode is unavailable, so configuration strength cannot be confirmed.",
                "Verify the key length and use an authenticated mode such as AES-256-GCM.",
                min(confidence, 0.75),
            )
        if asset.mode.upper() in {"ECB", "CBC"}:
            return _assessment(
                RiskSeverity.MEDIUM,
                f"AES uses {asset.mode.upper()}, which does not by itself provide authenticated encryption.",
                "Prefer AES-256-GCM or another approved authenticated encryption mode.",
                confidence,
            )
        return _assessment(
            RiskSeverity.LOW,
            "AES has a strong key length and a recognized modern configuration.",
            "Continue using approved key management and authenticated encryption practices.",
            confidence,
        )

    if algorithm in {"SHA-256", "SHA256", "SHA-512", "SHA512", "SHA-3", "SHA3"}:
        return _assessment(
            RiskSeverity.INFO,
            f"{asset.algorithm} is a modern approved hashing primitive.",
            "Continue monitoring implementation and key-management requirements where applicable.",
            confidence,
        )

    if algorithm in {"CERTIFICATE", "CERT"} or category == "certificate_or_key":
        return _assessment(
            RiskSeverity.MEDIUM,
            "A certificate or key was detected, but its cryptographic parameters are unavailable.",
            "Inspect the key algorithm, size, validity, and signature algorithm separately.",
            min(confidence, 0.75),
        )

    return _assessment(
        RiskSeverity.MEDIUM,
        f"The strength of {asset.algorithm} cannot be established from the available metadata.",
        "Review the primitive and its parameters against the approved cryptography policy.",
        min(confidence, 0.75),
    )


def classify_assets(assets: Iterable[CryptoAsset]) -> List[RiskAssessment]:
    """Classify assets in input order without changing the assets."""
    return [classify_asset(asset) for asset in assets]