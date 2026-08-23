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
