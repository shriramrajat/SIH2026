import pytest
import sys
from pathlib import Path

src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ecdat.scanner import Scanner
from ecdat.risk import classify_assets, RiskSeverity, QuantumThreat

@pytest.fixture
def scanner():
    return Scanner()

def test_integration_java_desede_produces_3des_high(scanner, tmp_path):
    java_source = tmp_path / "TestCipher.java"
    java_source.write_text('Cipher.getInstance("DESede/CBC/PKCS5Padding");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "3DES"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.HIGH
    assert risk.quantum_threat == QuantumThreat.NONE
    assert risk.pqc_recommendation is not None
    assert risk.pqc_recommendation.target_algorithm == "AES-256-GCM"

def test_integration_java_ecdh_produces_ecdh_critical(scanner, tmp_path):
    java_source = tmp_path / "TestKeyAgreement.java"
    java_source.write_text('KeyAgreement.getInstance("ECDH");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "ECDH"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.quantum_threat == QuantumThreat.SHOR
    assert risk.pqc_recommendation is not None
    assert risk.pqc_recommendation.target_algorithm == "ML-KEM-768"

def test_integration_java_ecdsa_produces_ecdsa_critical(scanner, tmp_path):
    java_source = tmp_path / "TestSignature.java"
    java_source.write_text('Signature.getInstance("SHA256withECDSA");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "ECDSA"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.quantum_threat == QuantumThreat.SHOR
    assert risk.pqc_recommendation is not None
    assert risk.pqc_recommendation.target_algorithm == "ML-DSA-65"

def test_integration_java_dsa_produces_dsa_critical(scanner, tmp_path):
    java_source = tmp_path / "TestDSASignature.java"
    java_source.write_text('Signature.getInstance("SHA256withDSA");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "DSA"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.quantum_threat == QuantumThreat.SHOR
    assert risk.pqc_recommendation is not None
    assert risk.pqc_recommendation.target_algorithm == "ML-DSA-65"

def test_integration_java_rsa_signature_produces_mldsa(scanner, tmp_path):
    java_source = tmp_path / "TestRSASignature.java"
    java_source.write_text('Signature.getInstance("SHA256withRSA");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "RSA"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.quantum_threat == QuantumThreat.SHOR
    assert risk.pqc_recommendation is not None
    assert risk.pqc_recommendation.target_algorithm == "ML-DSA-65"

def test_integration_java_rsa_encryption_produces_mlkem(scanner, tmp_path):
    java_source = tmp_path / "TestRSACipher.java"
    java_source.write_text('Cipher.getInstance("RSA/ECB/PKCS1Padding");')
    
    assets = scanner.scan_file(java_source)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.algorithm == "RSA"
    
    risk = classify_assets(assets)[0]
    assert risk.severity == RiskSeverity.CRITICAL
    assert risk.quantum_threat == QuantumThreat.SHOR
    assert risk.pqc_recommendation is not None
    assert "ML-KEM-768" in risk.pqc_recommendation.target_algorithm
    assert "ML-DSA-65" not in risk.pqc_recommendation.target_algorithm
