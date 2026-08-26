# SIH 26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

## Problem Statement

| Field | Value |
|---|---|
| **PS ID** | SIH 26164 |
| **Theme** | Blockchain & Cybersecurity |
| **Scanner Owner** | Rohan (`rskusalkar78`) |
| **Validation Owner** | Matin (`shaikhmatin723-blip`) |
| **Tech Lead** | Rajat (`shriramrajat`) |

---

## What ECDAT Does

ECDAT is a **zero-dependency, context-aware static cryptographic asset discovery engine**. It scans source code repositories for cryptographic algorithm usages, PEM key/certificate headers, and extracts algorithm names, key lengths, cipher modes, and padding where available.

**Current implementation covers:**
- Recursive source-file discovery with directory exclusion
- Language detection by file extension
- Comment stripping before detection (Python `#`, Java/C `//`, C `/* */`)
- Python AST-based detection for deep structural analysis
- Regex-based detection for Python, Java, C/C++, and PEM files
- Structured `CryptoAsset` output with `Evidence`
- Deterministic SHA-256 asset IDs
- Repo-relative normalised file paths (forward slashes, no machine-specific prefixes)

---

## Architecture

```
Source Directory / File
        │
        ▼
┌─────────────────────┐
│  File Discovery     │  Scanner.discover_files()
│  (recursive walk)   │  Skips: .git, __pycache__, venv, node_modules, build, dist
└──────────┬──────────┘
           │  list[Path]
           ▼
┌─────────────────────┐
│  Language Detection │  _determine_language() — by file extension
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Comment Stripping  │  strip_comments_from_lines()
│  (per language)     │  Python: removes # lines
│                     │  Java/C: removes // and /* ... */ blocks
└──────────┬──────────┘
           │  cleaned lines + original lines
           ▼
    ┌──────┴──────────────┐
    │                     │
    ▼                     ▼
┌─────────┐         ┌──────────────────┐
│  Python │         │  Java / C / C++  │
│  AST    │         │  / PEM           │
│ Scanner │         │  Regex Scanner   │
└────┬────┘         └───────┬──────────┘
     │                      │
     └──────────┬───────────┘
                │  Deduplication: AST hits take priority over
                │  regex hits on the same line+algorithm
                ▼
┌─────────────────────────────────────────┐
│  CryptoAsset                            │
│  ├── asset_id  (deterministic SHA-256)  │
│  ├── algorithm, category               │
│  ├── file_path (repo-relative posix)   │
│  ├── line_number                       │
│  ├── language                          │
│  ├── library                           │
│  ├── confidence                        │
│  ├── key_length (where extracted)      │
│  ├── mode (where extracted)            │
│  ├── padding (where extracted)         │
│  └── evidence                          │
│      ├── code_snippet                  │
│      ├── detection_mechanism           │
│      └── matched_rule_id              │
└─────────────────────────────────────────┘
```

---

## Module Map

| Module | File | Responsibility |
|---|---|---|
| **Models** | `src/ecdat/models.py` | `CryptoAsset`, `Evidence` dataclasses; deterministic asset ID generation; path normalisation |
| **Scanner** | `src/ecdat/scanner.py` | File discovery, comment stripping, `scan_file()` / `scan()` orchestration, Java/C regex scanning, AST+regex deduplication |
| **Rules** | `src/ecdat/rules.py` | `RegexRule` dataclass; `REGEX_RULES` list covering Python, Java, C/C++, PEM patterns |
| **AST Parser** | `src/ecdat/ast_parser.py` | `PythonASTScanner` (`ast.NodeVisitor`); `scan_python_ast()` entry point |

---

## Supported File Types

| Extension(s) | Language tag | Detection method |
|---|---|---|
| `.py` | `python` | AST (primary) + Regex (supplementary) |
| `.java` | `java` | Regex |
| `.c`, `.h` | `c` | Regex |
| `.cpp`, `.hpp` | `cpp` | Regex (C rules applied) |
| `.pem`, `.crt`, `.key` | `pem` | Regex (PEM header markers) |

---

## Detection Mechanisms

### Python AST Detection (`ast_parser.py`)

Uses Python's `ast.NodeVisitor` to walk the parsed syntax tree. Detects structural call patterns — not surface text — which makes it immune to string formatting variations.

**Detected patterns:**

| Pattern | Algorithm | Key length? | Mode? |
|---|---|---|---|
| `RSA.generate(2048)` | RSA | ✅ (if literal integer) | — |
| `RSA.generate(var)` | RSA | ❌ (dynamic) | — |
| `AES.new(key, AES.MODE_CBC, ...)` | AES | — | ✅ |
| `hashes.SHA1()` | SHA-1 | — | — |
| `hashes.SHA256()` | SHA-256 | — | — |
| `hashes.SHA512()` | SHA-512 | — | — |
| `hashes.MD5()` | MD5 | — | — |
| `hashlib.md5()` | MD5 | — | — |
| `hashlib.sha1()` | SHA-1 | — | — |
| `hashlib.sha256()` | SHA-256 | — | — |
| `hashlib.sha512()` | SHA-512 | — | — |

AST detections are given confidence `0.95` (statically resolved) or `0.75` (dynamic/unresolved parameters).

### Regex Detection (`rules.py` + `scanner.py`)

Applied after comment stripping. Detection runs line-by-line against the stripped content, but the original (unstripped) line is used for the code snippet.

**Python regex rules:**

| Rule ID | Pattern | Algorithm | Library |
|---|---|---|---|
| `py-hashlib-md5` | `hashlib.md5(` | MD5 | hashlib |
| `py-hashlib-sha1` | `hashlib.sha1(` | SHA-1 | hashlib |
| `py-hashlib-sha256` | `hashlib.sha256(` | SHA-256 | hashlib |
| `py-hashlib-sha512` | `hashlib.sha512(` | SHA-512 | hashlib |
| `py-crypto-rsa-gen` | `RSA.generate(<n>` | RSA | PyCryptodome |
| `py-crypto-aes-new` | `AES.new(` | AES | PyCryptodome |
| `py-cryptography-sha1` | `hashes.SHA1()` | SHA-1 | cryptography |
| `py-cryptography-sha256` | `hashes.SHA256()` | SHA-256 | cryptography |
| `py-cryptography-mode-cbc` | `modes.CBC(` | AES | cryptography |
| `py-cryptography-mode-gcm` | `modes.GCM(` | AES | cryptography |

**Java regex rules:**

| Rule ID | Pattern | Dynamic parsing |
|---|---|---|
| `java-cipher-instance` | `Cipher.getInstance("...")` | Parses `algorithm/mode/padding` from transform string |
| `java-keypair-gen` | `KeyPairGenerator.getInstance("...")` | Extracts algorithm name |
| `java-message-digest` | `MessageDigest.getInstance("...")` | Extracts digest name |

**C / C++ regex rules:**

| Rule ID | Pattern | Algorithm | Key length | Mode |
|---|---|---|---|---|
| `c-openssl-rsa-gen` | `RSA_generate_key_ex(` | RSA | — | — |
| `c-openssl-evp-aes128-cbc` | `EVP_aes_128_cbc(` | AES | 128 | CBC |
| `c-openssl-evp-aes256-gcm` | `EVP_aes_256_gcm(` | AES | 256 | GCM |
| `c-openssl-evp-sha256` | `EVP_sha256(` | SHA-256 | — | — |
| `c-openssl-evp-sha1` | `EVP_sha1(` | SHA-1 | — | — |
| `c-openssl-evp-md5` | `EVP_md5(` | MD5 | — | — |
| `c-openssl-ec-new` | `EC_KEY_new_by_curve_name(` | ECC | — | — |
| `c-openssl-dh-new` | `DH_new(` | DH | — | — |

**PEM header rules (all languages):**

| Rule ID | Pattern | Algorithm | Category |
|---|---|---|---|
| `pem-rsa-private-key` | `-----BEGIN RSA PRIVATE KEY-----` | RSA | certificate_or_key |
| `pem-ec-private-key` | `-----BEGIN EC PRIVATE KEY-----` | ECC | certificate_or_key |
| `pem-certificate` | `-----BEGIN CERTIFICATE-----` | Certificate | certificate_or_key |

---

## Confidence Scores

| Score | Condition |
|---|---|
| `0.95` | AST structural match with statically resolved parameters |
| `0.90` | PEM header marker |
| `0.80` | Standard regex API invocation match |
| `0.75` | AST structural match with dynamic/unresolved parameters |

---

## CryptoAsset Fields

| Field | Type | Description |
|---|---|---|
| `asset_id` | `str` | Deterministic `crypto-{sha256(path:line:algo:lib:rule)[:12]}` |
| `name` | `str` | Human-readable name for the detection |
| `category` | `str` | `asymmetric_encryption`, `symmetric_encryption`, `hashing`, `key_exchange`, `certificate_or_key` |
| `algorithm` | `str` | e.g. `RSA`, `AES`, `SHA-256`, `MD5`, `ECC`, `DH`, `Certificate` |
| `file_path` | `str` | Repo-relative path, forward slashes, no machine prefix |
| `line_number` | `int` | 1-based line number in the original file |
| `language` | `str` | `python`, `java`, `c`, `cpp`, `pem` |
| `library` | `str` | `hashlib`, `PyCryptodome`, `cryptography`, `java.security`, `javax.crypto`, `OpenSSL`, `PEM` |
| `confidence` | `float` | See confidence scores above |
| `key_length` | `int \| None` | Extracted where available |
| `mode` | `str \| None` | Extracted where available (e.g. `CBC`, `GCM`) |
| `padding` | `str \| None` | Extracted where available (e.g. `PKCS5Padding`) |
| `evidence.code_snippet` | `str` | Original (non-stripped) source line |
| `evidence.detection_mechanism` | `str` | `ast`, `regex`, or `pem_header` |
| `evidence.matched_rule_id` | `str` | Rule ID that triggered the detection |

---

## Comment Stripping

Comments are stripped **before** regex detection so commented-out crypto code does not produce false positives. The original (unstripped) line is preserved for the `code_snippet` evidence field.

| Language | What is stripped |
|---|---|
| Python | Lines starting with `#` (after stripping whitespace) |
| Java | `//` single-line comments; `/* ... */` block comments (tracked across lines) |
| C / C++ | `//` single-line comments; `/* ... */` block comments (tracked across lines) |
| PEM / other | No comment stripping |

---

## Deduplication

For Python files, the scanner runs AST detection first, then regex detection. Any regex hit on the same `(line_number, algorithm)` pair as an existing AST hit is discarded. AST hits take priority because they carry higher confidence and richer structural information.

---

## Directory Exclusion

The scanner skips the following directories by default:

`.git`, `__pycache__`, `venv`, `.venv`, `node_modules`, `build`, `dist`

---

## Testing

**Current test count: 13 tests, all passing.**

Run via:

```bash
python 26164/tests/run_tests.py
```

Or with pytest:

```bash
python -m pytest 26164/tests/ -v
```

### Test Coverage

| Test | What it verifies |
|---|---|
| `test_01_file_discovery` | Recursive file discovery; ignored directories are excluded |
| `test_02_python_ast_and_regex` | Python AST RSA static (2048, confidence 0.95), dynamic (confidence 0.75), AES mode (CBC) extraction |
| `test_03_java_detection` | Java Cipher transformation string parsing (algo/mode/padding), KeyPairGenerator, MessageDigest |
| `test_04_c_detection` | C OpenSSL EVP patterns; AES-128-CBC and AES-256-GCM key length + mode extraction |
| `test_05_pem_detection` | PEM header markers; confidence 0.90; 2 assets in fixture |
| `test_06_line_numbers_and_snippets` | Every asset has `line_number > 0` and non-empty `code_snippet` |
| `test_07_clean_code_false_positives` | Clean code file produces zero detections |
| `test_08_full_directory_scan` | `scan()` on fixtures produces >10 assets; serialisation via `to_dict()` |
| `test_09_deterministic_asset_id` | Same input → same `asset_id`; different line → different ID; different algorithm → different ID |
| `test_10_path_normalization` | No `C:` / `/home/` prefixes; no backslashes |
| `test_11_structured_evidence` | `Evidence` object present; `code_snippet` matches property; `detection_mechanism` in allowed values |
| `test_12_language_exposure` | `language` field matches file extension (`python`, `java`, `c`, `pem`) |
| `test_13_comment_filtering` | Python: MD5 and RSA in comments → not detected, SHA-256/SHA-512 active → detected; Java/C: commented code excluded |

### Test Fixtures

| Fixture | Purpose |
|---|---|
| `sample_python.py` | Python file with hashlib, PyCryptodome, cryptography usages |
| `sample_java.java` | Java file with Cipher.getInstance, KeyPairGenerator, MessageDigest |
| `sample_c.c` | C file with OpenSSL EVP calls |
| `sample_keys.pem` | PEM file with RSA private key and EC private key headers |
| `clean_code.py` | Python file with no crypto — zero-detection baseline |
| `commented_code.py` | Python with some usages in comments, some active |
| `commented_java.java` | Java with some usages in comments, some active |
| `commented_c.c` | C with some usages in comments, some active |

---

## Programmatic Usage

```python
from pathlib import Path
from ecdat.scanner import Scanner

scanner = Scanner()
assets = scanner.scan(Path("26164/tests/fixtures"))

for asset in assets:
    print(f"[{asset.confidence}] {asset.algorithm} ({asset.category})")
    print(f"  File:      {asset.file_path}:{asset.line_number}")
    print(f"  Library:   {asset.library}")
    print(f"  Mechanism: {asset.evidence.detection_mechanism}")
    print(f"  Rule:      {asset.evidence.matched_rule_id}")
    print(f"  Snippet:   {asset.code_snippet}")
    if asset.key_length:
        print(f"  Key length: {asset.key_length}")
    if asset.mode:
        print(f"  Mode:      {asset.mode}")
```

---

## Current Limitations

1. **Dynamic reflection:** Indirect reflect-based calls in Java (`Class.forName(...)`) or dynamic `getattr` in Python are not symbolically executed and will not be detected.
2. **Multi-line expressions in Java/C:** Regex detection operates line-by-line. Function calls split across multiple lines may not be fully matched.
3. **Binary inspection:** Out of scope. Only plain-text source files are scanned.
4. **No CBOM output:** Structured CycloneDX CBOM generation is not yet implemented (planned Phase 3 — Matin's area).
5. **No quantum risk scoring:** Risk assessment against Shor's/Grover's algorithms is not yet implemented.
6. **No hardcoded-secret detection:** Scanning for hardcoded API keys, passwords, or tokens is not currently implemented.

---

## Detailed Documentation

| Document | Contents |
|---|---|
| [`Docs/CRYPTO_SCANNER_DESIGN.md`](Docs/CRYPTO_SCANNER_DESIGN.md) | Full architecture, Rohan/Matin data contract, P0 fixes, roadmap, test results |
| [`Docs/architecture.md`](Docs/architecture.md) | High-level architecture diagram |
| [`Docs/datastructure.md`](Docs/datastructure.md) | Data structure documentation |
| [`Docs/mvp.md`](Docs/mvp.md) | MVP scope definition |
