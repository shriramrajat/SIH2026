import pytest
import os
import json
import sys
from pathlib import Path

# Add src to path for imports
src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

@pytest.fixture
def temp_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    
    # Python file (RSA encryption)
    (repo / "encrypt.py").write_text("""
from Crypto.PublicKey import RSA
private_key = RSA.generate(2048)
    """)
    
    # Java file (RSA Signature + DESede + ECDH)
    (repo / "Auth.java").write_text("""
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
public class Auth {
    void sign() {
        Signature.getInstance("SHA256withRSA");
    }
    void encrypt() {
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
    void exchange() {
        KeyAgreement.getInstance("ECDH");
    }
}
    """)
    
    # Unknown algorithm file
    (repo / "unknown.py").write_text("""
# some unknown algorithm 
# rule: java-cipher-instance but with weird algorithm name
# Actually, the scanner uses regex. 
# We'll just test a known algorithm that isn't explicitly handled in risk.py, like IDEA.
    """)
    (repo / "UnknownCipher.java").write_text("""
import javax.crypto.Cipher;
public class U {
    void enc() {
        Cipher.getInstance("BLOWFISH");
    }
}
    """)
    
    return repo


def test_invalid_target_path():
    response = client.post("/api/v1/scan", json={"target_path": "/path/that/does/not/exist"})
    assert response.status_code == 200
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_INPUT"


def test_empty_repository(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    response = client.post("/api/v1/scan", json={"target_path": str(repo)})
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert data["summary"]["total_crypto_assets"] == 0
    assert len(data["findings"]) == 0


def test_valid_scan_json_serializable(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    assert response.status_code == 200
    data = response.json()
    
    # If it reached here, it's JSON serializable
    assert "summary" in data
    assert "findings" in data
    assert "metadata" in data


def test_rsa_encryption_and_signature_distinction(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    findings = data["findings"]
    
    rsa_enc = next(f for f in findings if f["algorithm"] == "RSA" and f["category"] == "asymmetric_encryption")
    assert "ML-KEM" in rsa_enc["risk"]["pqc_recommendation"]["target_algorithm"]
    assert "ML-DSA" not in rsa_enc["risk"]["pqc_recommendation"]["target_algorithm"]
    
    rsa_sig = next(f for f in findings if f["algorithm"] == "RSA" and f["category"] == "digital_signature")
    assert "ML-DSA" in rsa_sig["risk"]["pqc_recommendation"]["target_algorithm"]


def test_java_desede_produces_3des_high(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    findings = data["findings"]
    
    # We should have a 3DES finding
    des_finding = next(f for f in findings if f["algorithm"] == "3DES")
    assert des_finding["risk"]["severity"] == "high"


def test_java_ecdh_produces_ecdh_critical(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    findings = data["findings"]
    
    ecdh_finding = next(f for f in findings if f["algorithm"] == "ECDH")
    assert ecdh_finding["risk"]["severity"] == "critical"
    assert ecdh_finding["risk"]["quantum_threat"] == "shor"


def test_unknown_algorithm_handles_gracefully(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    findings = data["findings"]
    
    # BLOWFISH should be classified gracefully
    bf = next(f for f in findings if f["algorithm"] == "BLOWFISH")
    assert bf["risk"]["severity"] == "medium"
    assert bf["risk"]["quantum_threat"] == "none"


def test_asset_id_correctly_joins_and_counts_match(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    summary = data["summary"]
    findings = data["findings"]
    
    # severity counts match
    actual_sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        actual_sev_counts[f["risk"]["severity"]] += 1
        
    for k, v in actual_sev_counts.items():
        assert summary["severity_counts"][k] == v
        
    # quantum counts match
    actual_qt_counts = {"shor": 0, "grover": 0, "none": 0}
    for f in findings:
        actual_qt_counts[f["risk"]["quantum_threat"]] += 1
        
    for k, v in actual_qt_counts.items():
        assert summary["quantum_threat_counts"][k] == v


def test_language_filter(temp_repo):
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo), "language_filters": ["python"]})
    data = response.json()
    findings = data["findings"]
    
    # Should only find the RSA python file, not the java ones
    assert len(findings) == 1
    assert findings[0]["algorithm"] == "RSA"
    assert findings[0]["category"] == "asymmetric_encryption"


def test_scanner_failure(monkeypatch, temp_repo):
    # Mock scanner to raise exception
    def mock_discover(*args, **kwargs):
        raise Exception("Simulated failure")
    monkeypatch.setattr("ecdat.scanner.Scanner.discover_files", mock_discover)
    
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    
    assert "error" in data
    assert data["error"]["code"] == "SCANNER_FAILURE"


def test_analysis_failure(monkeypatch, temp_repo):
    # Mock analysis to raise exception
    def mock_classify(*args, **kwargs):
        raise Exception("Simulated analysis failure")
    monkeypatch.setattr("api.main.classify_assets", mock_classify)
    
    response = client.post("/api/v1/scan", json={"target_path": str(temp_repo)})
    data = response.json()
    
    assert "error" in data
    assert data["error"]["code"] == "ANALYSIS_FAILURE"
