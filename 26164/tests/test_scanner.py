"""
Comprehensive pytest suite for ECDAT Source Code Cryptographic Scanner.
"""

import sys
from pathlib import Path

# Ensure src/ is in python path
src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ecdat.scanner import Scanner
from ecdat.models import CryptoAsset

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_file_discovery():
    scanner = Scanner()
    files = scanner.discover_files(FIXTURES_DIR)
    file_names = {f.name for f in files}

    assert "sample_python.py" in file_names
    assert "sample_java.java" in file_names
    assert "sample_c.c" in file_names
    assert "sample_keys.pem" in file_names
    assert "clean_code.py" in file_names


def test_python_ast_and_regex_detection():
    scanner = Scanner()
    python_file = FIXTURES_DIR / "sample_python.py"
    assets = scanner.scan_file(python_file)

    algos = {a.algorithm for a in assets}
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert "SHA-256" in algos
    assert "RSA" in algos
    assert "AES" in algos

    # Check RSA 2048 AST static extraction
    rsa_2048 = [a for a in assets if a.algorithm == "RSA" and a.key_length == 2048]
    assert len(rsa_2048) >= 1
    assert rsa_2048[0].confidence == 0.95
    assert "RSA.generate(2048)" in rsa_2048[0].code_snippet

    # Check RSA dynamic extraction
    rsa_dynamic = [a for a in assets if a.algorithm == "RSA" and a.key_length is None]
    assert len(rsa_dynamic) >= 1
    assert rsa_dynamic[0].confidence == 0.75

    # Check AES mode extraction
    aes_assets = [a for a in assets if a.algorithm == "AES"]
    assert len(aes_assets) >= 1
    assert aes_assets[0].mode == "CBC"


def test_java_detection():
    scanner = Scanner()
    java_file = FIXTURES_DIR / "sample_java.java"
    assets = scanner.scan_file(java_file)

    algos = {a.algorithm for a in assets}
    assert "AES" in algos
    assert "RSA" in algos
    assert "ECC" in algos
    assert "MD5" in algos
    assert "SHA-256" in algos

    # Check Cipher getInstance transformation parsing
    aes_asset = next(a for a in assets if a.algorithm == "AES")
    assert aes_asset.mode == "CBC"
    assert aes_asset.padding == "PKCS5Padding"
    assert aes_asset.category == "symmetric_encryption"
    assert "Cipher.getInstance" in aes_asset.code_snippet


def test_c_detection():
    scanner = Scanner()
    c_file = FIXTURES_DIR / "sample_c.c"
    assets = scanner.scan_file(c_file)

    algos = {a.algorithm for a in assets}
    assert "RSA" in algos
    assert "AES" in algos
    assert "SHA-256" in algos
    assert "SHA-1" in algos
    assert "MD5" in algos

    # Check AES key length and mode extraction
    aes_128 = next(a for a in assets if a.algorithm == "AES" and a.key_length == 128)
    assert aes_128.mode == "CBC"
    assert aes_128.library == "OpenSSL"

    aes_256 = next(a for a in assets if a.algorithm == "AES" and a.key_length == 256)
    assert aes_256.mode == "GCM"
    assert aes_256.library == "OpenSSL"


def test_pem_detection():
    scanner = Scanner()
    pem_file = FIXTURES_DIR / "sample_keys.pem"
    assets = scanner.scan_file(pem_file)

    assert len(assets) == 2
    categories = {a.category for a in assets}
    assert "certificate_or_key" in categories
    assert assets[0].confidence == 0.90


def test_line_numbers_and_snippets():
    scanner = Scanner()
    c_file = FIXTURES_DIR / "sample_c.c"
    assets = scanner.scan_file(c_file)

    for asset in assets:
        assert asset.line_number > 0
        assert len(asset.code_snippet) > 0
        assert isinstance(asset.code_snippet, str)


def test_clean_code_false_positives():
    scanner = Scanner()
    clean_file = FIXTURES_DIR / "clean_code.py"
    assets = scanner.scan_file(clean_file)

    # Clean code must yield zero detections
    assert len(assets) == 0


def test_full_directory_scan():
    scanner = Scanner()
    assets = scanner.scan(FIXTURES_DIR)

    # Should detect assets across sample files, ignoring clean_code.py
    assert len(assets) > 10
    asset_dict = assets[0].to_dict()
    assert "asset_id" in asset_dict
    assert "algorithm" in asset_dict
    assert "confidence" in asset_dict
    assert "evidence" in asset_dict
    assert "language" in asset_dict


def test_deterministic_asset_id():
    scanner = Scanner()
    python_file = FIXTURES_DIR / "sample_python.py"
    assets_run1 = scanner.scan_file(python_file)
    assets_run2 = scanner.scan_file(python_file)

    # 1. Stability across runs
    assert len(assets_run1) == len(assets_run2)
    for a1, a2 in zip(assets_run1, assets_run2):
        assert a1.asset_id == a2.asset_id
        assert a1.asset_id.startswith("crypto-")

    # 2. Same input -> same asset_id
    a1 = assets_run1[0]
    a1_clone = CryptoAsset.create(
        name=a1.name,
        category=a1.category,
        algorithm=a1.algorithm,
        file_path=a1.file_path,
        line_number=a1.line_number,
        code_snippet=a1.code_snippet,
        library=a1.library,
        confidence=a1.confidence,
        language=a1.language,
        detection_mechanism=a1.evidence.detection_mechanism,
        matched_rule_id=a1.evidence.matched_rule_id,
    )
    assert a1.asset_id == a1_clone.asset_id

    # 3. Different line -> different asset_id
    a_diff_line = CryptoAsset.create(
        name=a1.name,
        category=a1.category,
        algorithm=a1.algorithm,
        file_path=a1.file_path,
        line_number=a1.line_number + 100,
        code_snippet=a1.code_snippet,
        library=a1.library,
        confidence=a1.confidence,
        language=a1.language,
        detection_mechanism=a1.evidence.detection_mechanism,
        matched_rule_id=a1.evidence.matched_rule_id,
    )
    assert a1.asset_id != a_diff_line.asset_id

    # 4. Different algorithm -> different asset_id
    a_diff_algo = CryptoAsset.create(
        name=a1.name,
        category=a1.category,
        algorithm="DIFFERENT_ALGO",
        file_path=a1.file_path,
        line_number=a1.line_number,
        code_snippet=a1.code_snippet,
        library=a1.library,
        confidence=a1.confidence,
        language=a1.language,
        detection_mechanism=a1.evidence.detection_mechanism,
        matched_rule_id=a1.evidence.matched_rule_id,
    )
    assert a1.asset_id != a_diff_algo.asset_id


def test_path_normalization():
    scanner = Scanner()
    assets = scanner.scan(FIXTURES_DIR)
    for asset in assets:
        # Must not contain absolute Windows/Linux prefixes
        assert not asset.file_path.startswith("C:")
        assert not asset.file_path.startswith("c:")
        assert not asset.file_path.startswith("/home/")
        # Must use forward slashes
        assert "\\" not in asset.file_path


def test_structured_evidence():
    scanner = Scanner()
    python_file = FIXTURES_DIR / "sample_python.py"
    assets = scanner.scan_file(python_file)

    for asset in assets:
        assert asset.evidence is not None
        assert isinstance(asset.evidence.code_snippet, str)
        assert len(asset.evidence.code_snippet) > 0
        assert asset.evidence.detection_mechanism in ["ast", "regex", "pem_header"]
        assert isinstance(asset.evidence.matched_rule_id, str)
        # Property compatibility check
        assert asset.code_snippet == asset.evidence.code_snippet


def test_language_exposure():
    scanner = Scanner()
    python_assets = scanner.scan_file(FIXTURES_DIR / "sample_python.py")
    assert all(a.language == "python" for a in python_assets)

    java_assets = scanner.scan_file(FIXTURES_DIR / "sample_java.java")
    assert all(a.language == "java" for a in java_assets)

    c_assets = scanner.scan_file(FIXTURES_DIR / "sample_c.c")
    assert all(a.language == "c" for a in c_assets)

    pem_assets = scanner.scan_file(FIXTURES_DIR / "sample_keys.pem")
    assert all(a.language == "pem" for a in pem_assets)


def test_comment_filtering():
    scanner = Scanner()

    # Python commented code check
    py_assets = scanner.scan_file(FIXTURES_DIR / "commented_code.py")
    py_algos = {a.algorithm for a in py_assets}
    assert len(py_assets) == 2
    assert "SHA-256" in py_algos
    assert "SHA-512" in py_algos
    assert "MD5" not in py_algos
    assert "RSA" not in py_algos

    # Java commented code check
    java_assets = scanner.scan_file(FIXTURES_DIR / "commented_java.java")
    assert len(java_assets) == 1
    assert java_assets[0].algorithm == "AES"
    assert "AES/GCM/NoPadding" in java_assets[0].code_snippet
    assert not any("AES/CBC/PKCS5Padding" in a.code_snippet for a in java_assets)
    assert not any("DES/ECB/PKCS5Padding" in a.code_snippet for a in java_assets)

    # C commented code check
    c_assets = scanner.scan_file(FIXTURES_DIR / "commented_c.c")
    assert len(c_assets) == 1
    assert c_assets[0].algorithm == "AES"
    assert "EVP_aes_256_gcm" in c_assets[0].code_snippet
    assert not any("EVP_aes_128_cbc" in a.code_snippet for a in c_assets)
    assert not any("EVP_md5" in a.code_snippet for a in c_assets)
