"""Tests for deterministic ECDAT cryptographic asset risk classification."""

import sys
from pathlib import Path

src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ecdat.models import CryptoAsset
from ecdat.risk import RiskSeverity, QuantumThreat, classify_asset, classify_assets


def asset(algorithm, category, key_length=None, mode=None, padding=None, snippet="safe evidence"):
    return CryptoAsset.create(
        name=f"{algorithm} asset",
        category=category,
        algorithm=algorithm,
        file_path="fixture.py",
        line_number=1,
        code_snippet=snippet,
        library="test",
        confidence=0.95,
        key_length=key_length,
        mode=mode,
        padding=padding,
    )


def test_hardcoded_secret_is_critical_without_exposing_value():
    result = classify_asset(asset("SECRET", "hardcoded_secret", snippet="secret = 'TOP SECRET VALUE'"))
    assert result.severity == RiskSeverity.CRITICAL
    assert "TOP SECRET VALUE" not in result.reason
    assert result.pqc_recommendation is None
    assert result.quantum_threat == QuantumThreat.NONE


def test_legacy_algorithms_are_high():
    for algorithm in ("MD5", "SHA-1", "DES", "RC4"):
        res = classify_asset(asset(algorithm, "hashing"))
        assert res.severity == RiskSeverity.HIGH
        assert res.quantum_threat == QuantumThreat.NONE


def test_small_rsa_key_is_critical_and_shor_vulnerable():
    result = classify_asset(asset("RSA", "asymmetric_encryption", key_length=1024))
    assert result.severity == RiskSeverity.CRITICAL
    assert "1024" in result.reason
    assert result.quantum_threat == QuantumThreat.SHOR


def test_large_rsa_key_remains_shor_vulnerable():
    result = classify_asset(asset("RSA", "asymmetric_encryption", key_length=2048))
    assert result.severity == RiskSeverity.CRITICAL
    assert result.quantum_threat == QuantumThreat.SHOR

    result_4096 = classify_asset(asset("RSA", "asymmetric_encryption", key_length=4096))
    assert result_4096.severity == RiskSeverity.CRITICAL
    assert result_4096.quantum_threat == QuantumThreat.SHOR


def test_rsa_without_key_length_is_critical_but_lower_confidence():
    result = classify_asset(asset("RSA", "asymmetric_encryption"))
    assert result.severity == RiskSeverity.CRITICAL
    assert result.confidence == 0.75
    assert result.quantum_threat == QuantumThreat.SHOR


def test_aes128_is_medium_and_grover_vulnerable():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=128, mode="GCM"))
    assert result.severity == RiskSeverity.MEDIUM
    assert result.quantum_threat == QuantumThreat.GROVER


def test_aes128_mode_none_mentions_missing_mode():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=128, mode=None))
    assert result.severity == RiskSeverity.MEDIUM
    assert "mode is unavailable" in result.reason
    assert result.quantum_threat == QuantumThreat.GROVER


def test_aes192_is_medium_and_grover_vulnerable():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=192, mode="GCM"))
    assert result.severity == RiskSeverity.MEDIUM
    assert result.quantum_threat == QuantumThreat.GROVER


def test_aes256_gcm_is_low():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=256, mode="GCM", padding="NoPadding"))
    assert result.severity == RiskSeverity.LOW
    assert result.quantum_threat == QuantumThreat.NONE


def test_3des_is_high_severity():
    result = classify_asset(asset("3DES", "symmetric_encryption"))
    assert result.severity == RiskSeverity.HIGH
    assert result.quantum_threat == QuantumThreat.NONE


def test_ecdsa_and_ecdh_and_ecc_and_dsa_are_shor_vulnerable():
    for algo in ["ECDSA", "ECDH", "ECC", "DSA"]:
        result = classify_asset(asset(algo, "asymmetric_encryption"))
        assert result.severity == RiskSeverity.CRITICAL
        assert result.quantum_threat == QuantumThreat.SHOR
        assert result.pqc_recommendation is not None


def test_modern_hash_is_info_not_weak():
    for algorithm in ("SHA-256", "SHA-512", "SHA-3"):
        res = classify_asset(asset(algorithm, "hashing"))
        assert res.severity == RiskSeverity.INFO
        assert res.quantum_threat == QuantumThreat.NONE


def test_unknown_or_incomplete_asset_is_medium():
    result = classify_asset(asset("CustomCipher", "symmetric_encryption", padding=None))
    assert result.severity == RiskSeverity.MEDIUM
    assert result.confidence == 0.75
    assert result.quantum_threat == QuantumThreat.NONE


def test_empty_input_to_classify_assets():
    results = classify_assets([])
    assert results == []


def test_assessment_is_deterministic_and_assets_are_unchanged():
    original = asset("AES", "symmetric_encryption", key_length=256, mode="GCM")
    first = classify_asset(original)
    second = classify_asset(original)
    assert first == second
    assert original.to_dict()["algorithm"] == "AES"
    assert first.to_dict()["severity"] == "low"


def test_asset_id_propagation():
    a = asset("AES", "symmetric_encryption", key_length=256, mode="GCM")
    result = classify_asset(a)
    assert result.asset_id == a.asset_id


def test_structured_pqc_recommendation_serialization():
    result = classify_asset(asset("RSA", "asymmetric_encryption", key_length=2048))
    data = result.to_dict()
    assert "pqc_recommendation" in data
    pqc = data["pqc_recommendation"]
    assert pqc["target_algorithm"] == "ML-KEM-768"
    assert pqc["nist_standard"] == "FIPS 203"
    assert "migration_type" in pqc


def test_structured_quantum_threat_serialization():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=128, mode="GCM"))
    data = result.to_dict()
    assert data["quantum_threat"] == "grover"


def test_confidence_boundary_behavior():
    # Should clamp between 0.0 and 1.0
    a = asset("AES", "symmetric_encryption", key_length=256, mode="GCM")
    a.confidence = -0.5
    res = classify_asset(a)
    assert res.confidence == 0.0

    a.confidence = 1.5
    res = classify_asset(a)
    assert res.confidence == 1.0


def test_classify_assets_preserves_input_order():
    results = classify_assets([
        asset("MD5", "hashing"),
        asset("AES", "symmetric_encryption", key_length=256, mode="GCM"),
    ])
    assert [result.severity for result in results] == [RiskSeverity.HIGH, RiskSeverity.LOW]