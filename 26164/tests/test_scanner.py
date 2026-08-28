"""
Comprehensive pytest suite for ECDAT Source Code Cryptographic Scanner.
"""

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

# Ensure src/ is in python path
src_dir = Path(__file__).resolve().parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ecdat.scanner import Scanner
from ecdat.models import CryptoAsset

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _write_source(root: Path, relative_name: str, source: str) -> Path:
    path = root / relative_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source).strip() + "\n", encoding="utf-8")
    return path


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


def test_detection_matrix_core_language_capabilities():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_source(
            root,
            "matrix.py",
            """
            import hashlib
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import AES
            from cryptography.hazmat.primitives import hashes

            def run(key, nonce):
                hashlib.md5(b"legacy")
                hashlib.sha1(b"legacy")
                hashlib.sha256(b"modern")
                RSA.generate(2048)
                AES.new(key, AES.MODE_GCM, nonce=nonce)
                return hashes.SHA512()
            """,
        )
        _write_source(
            root,
            "Matrix.java",
            """
            import javax.crypto.Cipher;
            import java.security.KeyPairGenerator;
            import java.security.MessageDigest;

            class Matrix {
                void run() throws Exception {
                    Cipher.getInstance("AES/GCM/NoPadding");
                    Cipher.getInstance("DES/ECB/PKCS5Padding");
                    KeyPairGenerator.getInstance("RSA");
                    KeyPairGenerator.getInstance("EC");
                    MessageDigest.getInstance("MD5");
                    MessageDigest.getInstance("SHA-256");
                }
            }
            """,
        )
        _write_source(
            root,
            "matrix.c",
            """
            #include <openssl/evp.h>
            #include <openssl/rsa.h>

            void run(void) {
                RSA_generate_key_ex(rsa, 2048, bne, NULL);
                EVP_aes_128_cbc();
                EVP_aes_256_gcm();
                EVP_sha256();
                EVP_sha1();
                EVP_md5();
                EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                DH_new();
            }
            """,
        )

        assets = Scanner(root_dir=root).scan(root)

    py_assets = [a for a in assets if a.language == "python"]
    java_assets = [a for a in assets if a.language == "java"]
    c_assets = [a for a in assets if a.language == "c"]

    assert {a.algorithm for a in py_assets} == {"AES", "MD5", "RSA", "SHA-1", "SHA-256", "SHA-512"}
    assert any(a.algorithm == "RSA" and a.key_length == 2048 for a in py_assets)
    assert any(a.algorithm == "AES" and a.mode == "GCM" for a in py_assets)

    assert {a.algorithm for a in java_assets} == {"AES", "DES", "ECC", "MD5", "RSA", "SHA-256"}
    assert any(a.algorithm == "AES" and a.mode == "GCM" and a.padding == "NoPadding" for a in java_assets)
    assert any(a.algorithm == "DES" and a.mode == "ECB" for a in java_assets)

    assert {a.algorithm for a in c_assets} == {"AES", "DH", "ECC", "MD5", "RSA", "SHA-1", "SHA-256"}
    assert any(a.algorithm == "AES" and a.key_length == 128 and a.mode == "CBC" for a in c_assets)
    assert any(a.algorithm == "AES" and a.key_length == 256 and a.mode == "GCM" for a in c_assets)


def test_hardcoded_secret_detection_and_redaction():
    raw_values = [
        "ECDATSYNTHETICKEY1234567890",
        "ecdatsynthetic-db-pass-123",
        "ECDATSYNTHETICBYTES123",
    ]

    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_source(
            root,
            "hardcoded.py",
            """
            import os

            encryption_key = "ECDATSYNTHETICKEY1234567890"
            db_password: str = "ecdatsynthetic-db-pass-123"
            api_secret_bytes = b"ECDATSYNTHETICBYTES123"
            runtime_key = os.urandom(32)
            password_policy = "minimum-length-sixteen"
            """,
        )
        _write_source(
            root,
            "Hardcoded.java",
            """
            class Hardcoded {
                private static final String ENCRYPTION_KEY = "ECDATSYNTHETICKEY1234567890";
                private static final String DB_PASSWORD = "ecdatsynthetic-db-pass-123";
                private static final String KEY_ID = "ECDATSYNTHETICKEY1234567890";
                private static final String PUBLIC_KEY_LABEL = "ECDATSYNTHETICKEY1234567890";
                String runtimeKey = System.getenv("ECDAT_SYNTHETIC_KEY");
            }
            """,
        )
        _write_source(
            root,
            "hardcoded.c",
            """
            void hardcoded(void) {
                const char *encryption_key = "ECDATSYNTHETICKEY1234567890";
                static const char *db_password = "ecdatsynthetic-db-pass-123";
                const char *key_label = "ECDATSYNTHETICKEY1234567890";
                char token_buffer[32];
            }
            """,
        )

        assets = Scanner(root_dir=root).scan(root)

    secret_assets = [a for a in assets if a.category == "hardcoded_secret"]
    assert len(secret_assets) == 7
    assert {a.algorithm for a in secret_assets} == {"SECRET"}
    assert {a.language for a in secret_assets} == {"python", "java", "c"}
    assert all("***REDACTED***" in a.code_snippet for a in secret_assets)
    assert all(a.library == "source-code" for a in secret_assets)

    for raw_value in raw_values:
        assert all(raw_value not in a.code_snippet for a in secret_assets)
        assert all(raw_value not in a.evidence.code_snippet for a in secret_assets)


def test_key_like_strings_are_not_false_positives():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_source(
            root,
            "strings.py",
            """
            def docs():
                note = "hashlib.md5(b'legacy')"
                pem_text = "-----BEGIN RSA PRIVATE KEY-----"
                not_a_key = "ECDATSYNTHETICKEY1234567890"
                password_policy = "ecdatsynthetic-db-pass-123"
                return note, pem_text, not_a_key, password_policy
            """,
        )
        _write_source(
            root,
            "Strings.java",
            """
            class Strings {
                void docs() {
                    String doc = "Cipher.getInstance(\\"AES/CBC/PKCS5Padding\\")";
                    String apiKeyName = "ECDATSYNTHETICKEY1234567890";
                    String passwordPolicy = "ecdatsynthetic-db-pass-123";
                }
            }
            """,
        )
        _write_source(
            root,
            "strings.c",
            """
            void docs(void) {
                const char *doc = "EVP_md5() and EVP_aes_128_cbc() are documentation";
                const char *key_label = "ECDATSYNTHETICKEY1234567890";
                int value = 42;
            }
            """,
        )

        assets = Scanner(root_dir=root).scan(root)

    assert assets == []


def test_dynamic_generated_values_are_not_hardcoded_secrets():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_source(
            root,
            "dynamic.py",
            """
            import os
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes

            runtime_key = get_random_bytes(32)
            nonce = os.urandom(12)
            cipher = AES.new(runtime_key, AES.MODE_GCM, nonce=nonce)
            """,
        )
        _write_source(
            root,
            "Dynamic.java",
            """
            import javax.crypto.Cipher;

            class Dynamic {
                void run() throws Exception {
                    String apiSecret = System.getenv("ECDAT_SYNTHETIC_SECRET");
                    Cipher.getInstance("AES/GCM/NoPadding");
                }
            }
            """,
        )
        _write_source(
            root,
            "dynamic.c",
            """
            #include <openssl/evp.h>
            #include <openssl/rand.h>

            void run(void) {
                unsigned char encryption_key[32];
                RAND_bytes(encryption_key, sizeof(encryption_key));
                EVP_aes_256_gcm();
            }
            """,
        )

        assets = Scanner(root_dir=root).scan(root)

    assert not any(a.category == "hardcoded_secret" for a in assets)
    assert any(a.language == "python" and a.algorithm == "AES" and a.mode == "GCM" for a in assets)
    assert any(a.language == "java" and a.algorithm == "AES" and a.mode == "GCM" for a in assets)
    assert any(a.language == "c" and a.algorithm == "AES" and a.mode == "GCM" for a in assets)


def test_comment_markers_inside_strings_do_not_hide_active_code():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_source(
            root,
            "marker.py",
            """
            import hashlib
            note = "# not a source comment"; digest = hashlib.sha256(b"active")
            """,
        )
        _write_source(
            root,
            "Marker.java",
            """
            import javax.crypto.Cipher;

            class Marker {
                void run() throws Exception {
                    String url = "https://example.test"; Cipher.getInstance("AES/GCM/NoPadding");
                }
            }
            """,
        )
        _write_source(
            root,
            "marker.c",
            """
            #include <openssl/evp.h>

            void run(void) {
                const char *url = "https://example.test"; EVP_sha256();
            }
            """,
        )

        assets = Scanner(root_dir=root).scan(root)

    assert any(a.language == "python" and a.algorithm == "SHA-256" for a in assets)
    assert any(a.language == "java" and a.algorithm == "AES" and a.mode == "GCM" for a in assets)
    assert any(a.language == "c" and a.algorithm == "SHA-256" for a in assets)


def test_malformed_source_does_not_abort_regex_detection():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        broken_file = _write_source(
            root,
            "broken.py",
            """
            import hashlib
            legacy = hashlib.md5(b"legacy")
            def broken(:
                pass
            """,
        )

        assets = Scanner(root_dir=root).scan_file(broken_file, root_dir=root)

    assert len(assets) == 1
    assert assets[0].algorithm == "MD5"
    assert assets[0].confidence == 0.80
    assert assets[0].evidence.detection_mechanism == "regex"


def test_detected_assets_include_required_evidence_fields():
    assets = Scanner(root_dir=FIXTURES_DIR).scan(FIXTURES_DIR)

    assert assets
    for asset in assets:
        assert asset.asset_id
        assert asset.language in {"python", "java", "c", "pem"}
        assert asset.file_path
        assert asset.line_number > 0
        assert asset.category
        assert asset.algorithm
        assert asset.library
        assert asset.confidence is not None
        assert asset.evidence is not None
        assert asset.evidence.code_snippet
        assert asset.evidence.detection_mechanism in {"ast", "regex", "pem_header"}
        assert asset.evidence.matched_rule_id


def test_matrix_python():
    scanner = Scanner()
    assets = scanner.scan_file(FIXTURES_DIR / "matrix_python.py")

    algos = {a.algorithm for a in assets}
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert "SHA-256" in algos
    assert "SHA-512" in algos
    assert "RSA" in algos
    assert "AES" in algos
    assert "SECRET" in algos

    rsa_static = next(a for a in assets if a.algorithm == "RSA" and a.key_length == 2048)
    assert rsa_static.confidence == 0.95

    rsa_dynamic = next(a for a in assets if a.algorithm == "RSA" and a.key_length is None)
    assert rsa_dynamic.confidence == 0.75

    aes_cbc = next(a for a in assets if a.algorithm == "AES" and a.mode == "CBC" and a.library == "PyCryptodome")
    assert aes_cbc.confidence == 0.95

    secrets = [a for a in assets if a.algorithm == "SECRET"]
    assert len(secrets) == 2
    for s in secrets:
        assert "REDACTED" in s.code_snippet
        assert "AKIAIOSFODNN7EXAMPLE" not in s.code_snippet
        assert "SuperSecretPassword123!" not in s.code_snippet
        assert s.category == "hardcoded_secret"
        assert s.confidence == 0.85
        assert s.evidence.matched_rule_id == "py-ast-hardcoded-secret"


def test_matrix_java():
    scanner = Scanner()
    assets = scanner.scan_file(FIXTURES_DIR / "matrix_java.java")

    algos = {a.algorithm for a in assets}
    assert "AES" in algos
    assert "DES" in algos
    assert "RSA" in algos
    assert "ECC" in algos
    assert "DSA" in algos
    assert "SHA-256" in algos
    assert "MD5" in algos
    assert "SECRET" in algos

    aes_cbc = next(a for a in assets if a.algorithm == "AES" and a.mode == "CBC")
    assert aes_cbc.padding == "PKCS5Padding"
    assert aes_cbc.category == "symmetric_encryption"

    ecc = next(a for a in assets if a.algorithm == "ECC")
    assert ecc.category == "asymmetric_encryption"

    secrets = [a for a in assets if a.algorithm == "SECRET"]
    assert len(secrets) == 2
    for s in secrets:
        assert "REDACTED" in s.code_snippet


def test_matrix_c():
    scanner = Scanner()
    assets = scanner.scan_file(FIXTURES_DIR / "matrix_c.c")

    algos = {a.algorithm for a in assets}
    assert "RSA" in algos
    assert "ECC" in algos
    assert "DH" in algos
    assert "AES" in algos
    assert "SHA-1" in algos
    assert "SHA-256" in algos
    assert "MD5" in algos
    assert "SECRET" in algos

    aes_128 = next(a for a in assets if a.algorithm == "AES" and a.key_length == 128)
    assert aes_128.mode == "CBC"

    aes_256 = next(a for a in assets if a.algorithm == "AES" and a.key_length == 256)
    assert aes_256.mode == "GCM"


def test_matrix_pem():
    scanner = Scanner()
    assets = scanner.scan_file(FIXTURES_DIR / "matrix_pem.pem")

    algos = [a.algorithm for a in assets]
    assert "RSA" in algos
    assert "ECC" in algos
    assert "Certificate" in algos
    assert len(assets) == 4


def test_negative_cases():
    scanner = Scanner()

    py_assets = scanner.scan_file(FIXTURES_DIR / "negative_cases.py")
    assert len(py_assets) == 0

    java_assets = scanner.scan_file(FIXTURES_DIR / "negative_cases.java")
    assert len(java_assets) == 0

    c_assets = scanner.scan_file(FIXTURES_DIR / "negative_cases.c")
    assert len(c_assets) == 0


def test_deduplication_and_edge_cases():
    scanner = Scanner()

    # 1. Empty file
    empty_file = FIXTURES_DIR / "empty.py"
    empty_file.write_text("")
    assets = scanner.scan_file(empty_file)
    assert len(assets) == 0
    empty_file.unlink()

    # 2. Unsupported extension
    unsupported_file = FIXTURES_DIR / "test.txt"
    unsupported_file.write_text("hashlib.md5()")
    assets = scanner.scan_file(unsupported_file)
    assert len(assets) == 0
    unsupported_file.unlink()

    # 3. Unicode source
    unicode_file = FIXTURES_DIR / "unicode.py"
    unicode_file.write_text("# -*- coding: utf-8 -*-\n# Unicode comment: ðŸ”’ key\nhashlib.md5()", encoding="utf-8")
    assets = scanner.scan_file(unicode_file)
    assert len(assets) == 1
    assert assets[0].algorithm == "MD5"
    unicode_file.unlink()

    # 4. Multiple matches on one line
    multimatch_file = FIXTURES_DIR / "multi.py"
    multimatch_file.write_text("hashlib.md5(); hashlib.md5()")
    assets = scanner.scan_file(multimatch_file)
    assert len(assets) == 2
    multimatch_file.unlink()

    # 5. Multiple matches on one line in C (regex only)
    multimatch_c = FIXTURES_DIR / "multi_c.c"
    multimatch_c.write_text("EVP_sha256(); EVP_sha256();")
    assets = scanner.scan_file(multimatch_c)
    assert len(assets) == 2
    multimatch_c.unlink()

def test_file_failure_isolation():
    from unittest.mock import patch

    with TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Good file
        good_file = root / "good.py"
        good_file.write_text("import hashlib\nhashlib.md5()")

        # Bad file
        bad_file = root / "bad.java"
        bad_file.write_text('Cipher.getInstance("AES");')

        scanner = Scanner(root_dir=root)

        original_scan = scanner.scan_file_regex
        def mock_scan(file_path, lines, root_dir):
            if "bad.java" in str(file_path):
                raise RuntimeError("Simulated failure")
            return original_scan(file_path, lines, root_dir=root_dir)

        with patch.object(scanner, 'scan_file_regex', side_effect=mock_scan):
            assets = scanner.scan(root)

        # The good file (Python) still succeeds!
        assert len(assets) == 1
        assert assets[0].algorithm == "MD5"

        # Errors should be recorded
        assert len(scanner.errors) == 1
        assert "bad.java" in scanner.errors[0]["file"]
        assert "Simulated failure" in scanner.errors[0]["error"]

def test_resource_and_symlink_safety():
    from unittest.mock import patch
    with TemporaryDirectory() as tmp:
        root = Path(tmp)

        # 1. oversized file
        large_file = root / "large.py"
        large_file.write_text("A" * 1024)

        # 2. normal file
        normal_file = root / "normal.py"
        normal_file.write_text("hashlib.md5()")

        # 3. fake unsafe symlink
        symlink_file = root / "symlink.py"
        symlink_file.write_text("hashlib.md5()")

        # Set a small limit
        scanner = Scanner(root_dir=root, max_file_size_bytes=500)

        # Mock Path.is_symlink and Path.resolve for symlink_file
        original_is_symlink = Path.is_symlink
        original_resolve = Path.resolve

        def mock_is_symlink(self):
            if self.name == "symlink.py":
                return True
            return original_is_symlink(self)

        def mock_resolve(self, *args, **kwargs):
            if self.name == "symlink.py":
                # Returns a path outside root
                return Path("/outside/root/target.py")
            return original_resolve(self, *args, **kwargs)

        with patch.object(Path, 'is_symlink', mock_is_symlink):
            with patch.object(Path, 'resolve', mock_resolve):
                assets = scanner.scan(root)

        assert len(assets) == 1
        assert assets[0].algorithm == "MD5"

        # large.py should be oversized
        assert any("large.py" in s["file"] and s["reason"] == "oversized" for s in scanner.skipped_files)

        # symlink.py should be unsafe_symlink
        assert any("symlink.py" in s["file"] and s["reason"] == "unsafe_symlink" for s in scanner.skipped_files)
