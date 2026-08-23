"""
Detection Rule Specifications for ECDAT Source Code Cryptographic Scanner.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class RegexRule:
    rule_id: str
    name: str
    language: str  # 'python', 'java', 'c', 'cpp', 'all'
    pattern: re.Pattern
    algorithm: str
    category: str
    library: str
    confidence: float = 0.80
    key_length: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None


# Language specific and general regex detection rules
REGEX_RULES: List[RegexRule] = [
    # ------------------ PYTHON RULES ------------------
    RegexRule(
        rule_id="py-hashlib-md5",
        name="Python hashlib MD5",
        language="python",
        pattern=re.compile(r"\bhashlib\.md5\s*\("),
        algorithm="MD5",
        category="hashing",
        library="hashlib",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-hashlib-sha1",
        name="Python hashlib SHA-1",
        language="python",
        pattern=re.compile(r"\bhashlib\.sha1\s*\("),
        algorithm="SHA-1",
        category="hashing",
        library="hashlib",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-hashlib-sha256",
        name="Python hashlib SHA-256",
        language="python",
        pattern=re.compile(r"\bhashlib\.sha256\s*\("),
        algorithm="SHA-256",
        category="hashing",
        library="hashlib",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-hashlib-sha512",
        name="Python hashlib SHA-512",
        language="python",
        pattern=re.compile(r"\bhashlib\.sha512\s*\("),
        algorithm="SHA-512",
        category="hashing",
        library="hashlib",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-crypto-rsa-gen",
        name="Python PyCryptodome RSA Generate",
        language="python",
        pattern=re.compile(r"\bRSA\.generate\s*\(\s*(\d+)"),
        algorithm="RSA",
        category="asymmetric_encryption",
        library="PyCryptodome",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-crypto-aes-new",
        name="Python PyCryptodome AES New",
        language="python",
        pattern=re.compile(r"\bAES\.new\s*\("),
        algorithm="AES",
        category="symmetric_encryption",
        library="PyCryptodome",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-cryptography-sha1",
        name="Python Cryptography SHA-1",
        language="python",
        pattern=re.compile(r"\bhashes\.SHA1\s*\(\s*\)"),
        algorithm="SHA-1",
        category="hashing",
        library="cryptography",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-cryptography-sha256",
        name="Python Cryptography SHA-256",
        language="python",
        pattern=re.compile(r"\bhashes\.SHA256\s*\(\s*\)"),
        algorithm="SHA-256",
        category="hashing",
        library="cryptography",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="py-cryptography-mode-cbc",
        name="Python Cryptography Mode CBC",
        language="python",
        pattern=re.compile(r"\bmodes\.CBC\s*\("),
        algorithm="AES",
        category="symmetric_encryption",
        library="cryptography",
        confidence=0.80,
        mode="CBC",
    ),
    RegexRule(
        rule_id="py-cryptography-mode-gcm",
        name="Python Cryptography Mode GCM",
        language="python",
        pattern=re.compile(r"\bmodes\.GCM\s*\("),
        algorithm="AES",
        category="symmetric_encryption",
        library="cryptography",
        confidence=0.80,
        mode="GCM",
    ),

    # ------------------ JAVA RULES ------------------
    RegexRule(
        rule_id="java-cipher-instance",
        name="Java Cipher getInstance",
        language="java",
        pattern=re.compile(r'\bCipher\.getInstance\s*\(\s*"([^"]+)"\s*\)'),
        algorithm="AES",  # Dynamically parsed in scanner if different
        category="symmetric_encryption",
        library="javax.crypto",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="java-keypair-gen",
        name="Java KeyPairGenerator getInstance",
        language="java",
        pattern=re.compile(r'\bKeyPairGenerator\.getInstance\s*\(\s*"([^"]+)"\s*\)'),
        algorithm="RSA",  # Dynamically parsed
        category="asymmetric_encryption",
        library="java.security",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="java-message-digest",
        name="Java MessageDigest getInstance",
        language="java",
        pattern=re.compile(r'\bMessageDigest\.getInstance\s*\(\s*"([^"]+)"\s*\)'),
        algorithm="SHA-256",  # Dynamically parsed
        category="hashing",
        library="java.security",
        confidence=0.80,
    ),

    # ------------------ C / C++ RULES ------------------
    RegexRule(
        rule_id="c-openssl-rsa-gen",
        name="C/C++ OpenSSL RSA Generate Key",
        language="c",
        pattern=re.compile(r"\bRSA_generate_key_ex\s*\("),
        algorithm="RSA",
        category="asymmetric_encryption",
        library="OpenSSL",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="c-openssl-evp-aes128-cbc",
        name="C/C++ OpenSSL EVP AES-128-CBC",
        language="c",
        pattern=re.compile(r"\bEVP_aes_128_cbc\s*\("),
        algorithm="AES",
        category="symmetric_encryption",
        library="OpenSSL",
        confidence=0.80,
        key_length=128,
        mode="CBC",
    ),
    RegexRule(
        rule_id="c-openssl-evp-aes256-gcm",
        name="C/C++ OpenSSL EVP AES-256-GCM",
        language="c",
        pattern=re.compile(r"\bEVP_aes_256_gcm\s*\("),
        algorithm="AES",
        category="symmetric_encryption",
        library="OpenSSL",
        confidence=0.80,
        key_length=256,
        mode="GCM",
    ),
    RegexRule(
        rule_id="c-openssl-evp-sha256",
        name="C/C++ OpenSSL EVP SHA-256",
        language="c",
        pattern=re.compile(r"\bEVP_sha256\s*\("),
        algorithm="SHA-256",
        category="hashing",
        library="OpenSSL",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="c-openssl-evp-sha1",
        name="C/C++ OpenSSL EVP SHA-1",
        language="c",
        pattern=re.compile(r"\bEVP_sha1\s*\("),
        algorithm="SHA-1",
        category="hashing",
        library="OpenSSL",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="c-openssl-evp-md5",
        name="C/C++ OpenSSL EVP MD5",
        language="c",
        pattern=re.compile(r"\bEVP_md5\s*\("),
        algorithm="MD5",
        category="hashing",
        library="OpenSSL",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="c-openssl-ec-new",
        name="C/C++ OpenSSL EC Key New",
        language="c",
        pattern=re.compile(r"\bEC_KEY_new_by_curve_name\s*\("),
        algorithm="ECC",
        category="asymmetric_encryption",
        library="OpenSSL",
        confidence=0.80,
    ),
    RegexRule(
        rule_id="c-openssl-dh-new",
        name="C/C++ OpenSSL DH New",
        language="c",
        pattern=re.compile(r"\bDH_new\s*\("),
        algorithm="DH",
        category="key_exchange",
        library="OpenSSL",
        confidence=0.80,
    ),

    # ------------------ ALL / PEM MARKERS ------------------
    RegexRule(
        rule_id="pem-rsa-private-key",
        name="PEM RSA Private Key Header",
        language="all",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        algorithm="RSA",
        category="certificate_or_key",
        library="PEM",
        confidence=0.90,
    ),
    RegexRule(
        rule_id="pem-ec-private-key",
        name="PEM EC Private Key Header",
        language="all",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        algorithm="ECC",
        category="certificate_or_key",
        library="PEM",
        confidence=0.90,
    ),
    RegexRule(
        rule_id="pem-certificate",
        name="PEM Certificate Header",
        language="all",
        pattern=re.compile(r"-----BEGIN CERTIFICATE-----"),
        algorithm="Certificate",
        category="certificate_or_key",
        library="PEM",
        confidence=0.90,
    ),
]
