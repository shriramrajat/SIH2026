"""Tests for deterministic ECDAT cryptographic asset risk classification."""

import sys
from pathlib import Path

src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ecdat.models import CryptoAsset
from ecdat.risk import RiskSeverity, classify_asset, classify_assets


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
    assert "TOP SECRET VALUE" not in result.recommendation


def test_legacy_algorithms_are_high():
    for algorithm in ("MD5", "SHA-1", "DES", "RC4"):
        assert classify_asset(asset(algorithm, "hashing")).severity == RiskSeverity.HIGH


def test_small_rsa_key_is_high():
    result = classify_asset(asset("RSA", "asymmetric_encryption", key_length=1024))
    assert result.severity == RiskSeverity.HIGH
    assert "1024" in result.reason


def test_rsa_without_key_length_is_critical_but_lower_confidence():
    result = classify_asset(asset("RSA", "asymmetric_encryption"))
    assert result.severity == RiskSeverity.CRITICAL
    assert result.confidence == 0.75


def test_aes128_is_medium():
    assert classify_asset(asset("AES", "symmetric_encryption", key_length=128, mode="GCM")).severity == RiskSeverity.MEDIUM


def test_aes_missing_parameters_is_medium():
    result = classify_asset(asset("AES", "symmetric_encryption"))
    assert result.severity == RiskSeverity.MEDIUM
    assert "unavailable" in result.reason


def test_aes256_gcm_is_low():
    result = classify_asset(asset("AES", "symmetric_encryption", key_length=256, mode="GCM", padding="NoPadding"))
    assert result.severity == RiskSeverity.LOW


def test_modern_hash_is_info_not_weak():
    for algorithm in ("SHA-256", "SHA-512"):
        assert classify_asset(asset(algorithm, "hashing")).severity == RiskSeverity.INFO


def test_unknown_or_incomplete_asset_is_medium():
    result = classify_asset(asset("CustomCipher", "symmetric_encryption", padding=None))
    assert result.severity == RiskSeverity.MEDIUM
    assert result.confidence == 0.75


def test_assessment_is_deterministic_and_assets_are_unchanged():
    original = asset("AES", "symmetric_encryption", key_length=256, mode="GCM")
    first = classify_asset(original)
    second = classify_asset(original)
    assert first == second
    assert original.to_dict()["algorithm"] == "AES"
    assert first.to_dict()["severity"] == "low"


def test_classify_assets_preserves_input_order():
    results = classify_assets([
        asset("MD5", "hashing"),
        asset("AES", "symmetric_encryption", key_length=256, mode="GCM"),
    ])
    assert [result.severity for result in results] == [RiskSeverity.HIGH, RiskSeverity.LOW]