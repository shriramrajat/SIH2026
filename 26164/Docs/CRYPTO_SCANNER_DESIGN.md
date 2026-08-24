# PS 26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Crypto Scanner Technical Design & Data Contract Specification

**Owner**: Rohan (rskusalkar78) — Crypto Discovery & Scanner  
**Consumer**: Matin — Crypto Intelligence, CBOM, Risk Engine, Quantum & PQC Migration  
**Date**: August 24, 2026  
**Document Status**: Baseline Technical Design & Audit Specification  
**Target File**: `26164/docs/CRYPTO_SCANNER_DESIGN.md`

---

## 1. Executive Summary & Ownership Boundaries

### The Core System Architecture & Separation of Concerns

```
             ROHAN (Ownership Area)
        Crypto Discovery & Scanner Engine
                       │
                       │ Produces Canonical Output
                       ▼
            ┌─────────────────────┐
            │     CryptoAsset     │  ← STABLE CONTRACT BOUNDARY
            └──────────┬──────────┘
                       │ Consumes Canonical Output
                       ▼
             MATIN (Ownership Area)
          Cryptographic Intelligence
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
    CBOM 1.6      Risk Engine      Quantum Analysis
  (CycloneDX)   (Vulnerability)    (Shor's/Grover's)
                                      │
                                      ▼
                               PQC Migration Plan
```

* **Rohan's Ownership**: Discovery, file traversal, language detection, AST/regex extraction, evidence capture (file path, line number, snippet), raw parameter extraction (algorithm, key length, mode, padding, library), asset deduplication, and normalization into `CryptoAsset`. Rohan owns **detection truth**.
* **Matin's Ownership**: Consumes `CryptoAsset` objects to perform vulnerability assessment, quantum threat evaluation (Shor's / Grover's algorithms), risk scoring, CycloneDX 1.6 CBOM serialization, and NIST PQC migration pathing (FIPS 203 / 204 / 205). Matin owns **interpretation of truth**.

---

## 2. Task 1 — Current Scanner Audit

A comprehensive audit of the baseline ECDAT scanner codebase (`26164/src/ecdat/`).

### 2.1 Supported Languages & File Extensions
| Language | File Extensions | Detection Mechanisms Supported |
| :--- | :--- | :--- |
| **Python** | `.py` | Dual-pass: Python `ast` visitor (`PythonASTScanner`) + Regular Expressions (`scan_file_regex`) |
| **Java** | `.java` | Regular Expressions (`RegexRule`) + Dynamic transformation string splitting (`Cipher.getInstance`) |
| **C** | `.c`, `.h` | Regular Expressions (`RegexRule`) targeting OpenSSL EVP and legacy C APIs |
| **C++** | `.cpp`, `.hpp` | Regular Expressions (`RegexRule`) with C-rule fallback inheritance |
| **Keys / Certificates** | `.pem`, `.crt`, `.key` | Regular Expressions (`RegexRule`) targeting standard PEM header markers |

### 2.2 Supported Cryptographic Algorithms & Primitives
* **Asymmetric Key Algorithms**: RSA, ECC (ECDSA, ECDH), Diffie-Hellman (DH), DSA.
* **Symmetric Ciphers**: AES (modes: CBC, GCM, ECB, CTR).
* **Cryptographic Hash / Digest Functions**: MD5, SHA-1, SHA-256, SHA-512.
* **Key & Certificate Containers**: PEM RSA Private Keys, PEM EC Private Keys, PEM X.509 Certificates.
* **Tracked Crypto Libraries**: `hashlib`, `PyCryptodome`, `cryptography` (Python); `javax.crypto`, `java.security` (Java); `OpenSSL` (C/C++); `PEM` (Headers).

### 2.3 Current Detection Mechanisms
1. **File Discovery (`Scanner.discover_files`)**:
   - Recursively traverses root directory trees via `os.walk`.
   - Filters by `SUPPORTED_EXTENSIONS` (`.py`, `.java`, `.c`, `.cpp`, `.h`, `.hpp`, `.pem`, `.crt`, `.key`).
   - Ignores default directories: `.git`, `__pycache__`, `node_modules`, `venv`, `.venv`, `build`, `dist`, `.idea`, `.vscode`.
2. **Language Classification (`Scanner._determine_language`)**:
   - Maps extension `.py` $\rightarrow$ `python`, `.java` $\rightarrow$ `java`, `.c`/`.h` $\rightarrow$ `c`, `.cpp`/`.hpp` $\rightarrow$ `cpp`, others $\rightarrow$ `all`.
3. **AST Visitor (`PythonASTScanner` in `ast_parser.py`)**:
   - Uses standard library `ast.NodeVisitor` to inspect syntax nodes on Python code.
   - Detects `RSA.generate(...)`: extracts integer `key_length` constant from positional arg `0`.
   - Detects `AES.new(...)`: inspects `ast.Attribute` nodes for mode flags (`MODE_CBC`, `MODE_GCM`, `CBC`, `GCM`, `ECB`, `CTR`).
   - Detects `hashes.<ALGO>()` (`cryptography` library) and `hashlib.<algo>()` (`hashlib` library).
4. **Regex Pattern Engine (`Scanner.scan_file_regex` in `rules.py`)**:
   - Evaluates 19 pre-compiled `RegexRule` objects against non-empty source lines.
   - Performs dynamic string parsing for Java rules:
     - `Cipher.getInstance("AES/CBC/PKCS5Padding")` $\rightarrow$ splits by `/` to extract algorithm (`AES`), mode (`CBC`), padding (`PKCS5Padding`).
     - `KeyPairGenerator.getInstance("EC")` $\rightarrow$ normalizes algorithm name to `ECC`.
     - `MessageDigest.getInstance("SHA-256")` $\rightarrow$ extracts algorithm name (`SHA-256`).
5. **AST / Regex Deduplication (`Scanner.scan_file`)**:
   - For Python files, AST hits take precedence.
   - Regex hits matching the same line number and algorithm `(line_number, algorithm)` as an AST hit are filtered out.

### 2.4 Current Output & Dataclass Structure
In `26164/src/ecdat/models.py`, `CryptoAsset` currently has 12 fields:
```python
@dataclass
class CryptoAsset:
    asset_id: str
    name: str
    category: str
    algorithm: str
    file_path: str
    line_number: int
    code_snippet: str
    library: str
    confidence: float
    key_length: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
```

### 2.5 Evidence Structure
* `file_path`: String filepath (currently absolute path from `Path.resolve()`).
* `line_number`: 1-indexed integer line location.
* `code_snippet`: Stripped string representation of the source line.

### 2.6 Confidence Scoring Model
* **`0.95`**: AST structural match with statically resolved parameter values (e.g. `RSA.generate(2048)`).
* **`0.90`**: Unambiguous PEM file header markers (e.g. `-----BEGIN RSA PRIVATE KEY-----`).
* **`0.80`**: Standard Regex API pattern invocation match.
* **`0.75`**: AST structural match with dynamic or unresolved variable parameters (e.g. `RSA.generate(var_bits)`).

### 2.7 Line & File Tracking
* `line_number` is captured from `enumerate(content_lines, start=1)` for regex matches and `node.lineno` for AST nodes.
* Snippets are stripped single lines fetched via line index.

### 2.8 Duplicate Detection & False-Positive Handling
* **Duplicates**: Only Python files deduplicate AST vs Regex matches on the exact line and algorithm tuple `(line_number, algorithm)`. Java, C, C++, and PEM files do not deduplicate. Multiple regex matches on the same line will emit duplicate asset entries.
* **False Positives**: Skip empty lines. Python AST ignores comments and string literals because it parses real syntax. Regex rules currently match raw line strings without checking for code comments (`//`, `#`, `/* */`) or docstrings.

---

## 3. Task 2 — Proposed Canonical CryptoAsset Schema Contract

This contract defines the exact JSON/Dataclass structure produced by Rohan's scanner and consumed by Matin's intelligence layer.

```json
{
  "asset_id": "crypto-a1b2c3d4",
  "file_path": "src/auth/crypto.py",
  "line_number": 42,
  "language": "python",
  "algorithm": "RSA",
  "primitive": "public-key-encryption",
  "library": "PyCryptodome",
  "confidence": 0.95,
  "evidence": {
    "code_snippet": "key = RSA.generate(2048)",
    "detection_mechanism": "ast",
    "matched_rule_id": "py-ast-rsa-gen"
  },
  "key_size": 2048,
  "mode": null,
  "padding": null,
  "operation": "keygen",
  "usage": "asymmetric_key_generation"
}
```

### Complete Field Specification Matrix

| Field | Type | Req/Opt | Description / Meaning | Current Availability | Source in Scanner |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `asset_id` | `str` | **Required** | Deterministic unique asset identifier string | Available | `f"crypto-{uuid.uuid4().hex[:8]}"` (Needs deterministic SHA-256 hash upgrade) |
| `file_path` | `str` | **Required** | Normalized relative path from target repo root | Available (Absolute) | `str(file_path)` (Needs `relative_to(root)` normalization) |
| `line_number` | `int` | **Required** | 1-indexed source line location | Available | `node.lineno` (AST) / line `idx` (Regex) |
| `language` | `str` | **Required** | Programming language ('python', 'java', 'c', 'cpp', 'pem') | Internal Only | `_determine_language(file_path)` (Not currently exposed on `CryptoAsset`) |
| `algorithm` | `str` | **Required** | Standardized algorithm identifier (e.g. "RSA", "AES", "SHA-256", "ECC", "ECDH", "MD5") | Available | AST mapping / `RegexRule.algorithm` |
| `primitive` | `str` | **Required** | CycloneDX-aligned primitive ('symmetric-cipher', 'public-key-encryption', 'message-digest', 'key-exchange', 'digital-signature', 'mac', 'kdf', 'certificate') | Partially Available | Currently stored as coarse `category` ('symmetric_encryption', 'asymmetric_encryption', 'hashing', 'key_exchange', 'certificate_or_key') |
| `library` | `str` | **Required** | Identified crypto framework/library (e.g., 'PyCryptodome', 'hashlib', 'cryptography', 'javax.crypto', 'OpenSSL') | Available | AST visitor / `RegexRule.library` |
| `confidence` | `float` | **Required** | Normalized detection confidence score (0.00 to 1.00) | Available | AST score (0.95/0.75), PEM (0.90), Regex (0.80) |
| `evidence` | `dict` / `Evidence` | **Required** | Nested evidence object containing `code_snippet`, `detection_mechanism`, `matched_rule_id` | Partially Available | `code_snippet` is a top-level string on `CryptoAsset`; mechanism & rule ID are lost |
| `key_size` | `Optional[int]` | **Optional** | Extracted key bit length (e.g., 128, 256, 2048, 4096). Null if unknown/unextracted. | Partially Available | AST positional integer arg / OpenSSL regex name (`EVP_aes_128_cbc`) |
| `mode` | `Optional[str]` | **Optional** | Block cipher operating mode (e.g., "CBC", "GCM", "ECB", "CTR"). Null if N/A. | Partially Available | AST attribute inspection / Java Cipher string split / OpenSSL regex |
| `padding` | `Optional[str]` | **Optional** | Padding scheme (e.g., "PKCS5Padding", "OAEP", "PSS"). Null if N/A. | Partially Available | Java Cipher string split |
| `operation` | `Optional[str]` | **Optional** | Cryptographic operation type ('keygen', 'encrypt', 'decrypt', 'digest', 'sign', 'verify', 'key-exchange') | **Unproduced** | Missing in current scanner |
| `usage` | `Optional[str]` | **Optional** | Static contextual usage indicator ('data-in-transit', 'data-at-rest', 'auth-token', 'cert-storage') | **Unproduced** | Missing in current scanner |

---

## 4. Task 3 — Current Scanner Output $\rightarrow$ CryptoAsset Mapping

```
Current Scanner Output (models.py)                Proposed Canonical CryptoAsset Schema
┌────────────────────────────────┐                ┌──────────────────────────────────┐
│ CryptoAsset                    │                │ CryptoAsset                      │
├────────────────────────────────┤                ├──────────────────────────────────┤
│ asset_id: str                  │ ─────────────► │ asset_id: str (deterministic)    │
│ name: str                      │ ── (Merged) ─► │ evidence.matched_rule_id / usage │
│ category: str                  │ ─────────────► │ primitive: str (CycloneDX standard)│
│ algorithm: str                 │ ─────────────► │ algorithm: str                   │
│ file_path: str                 │ ─────────────► │ file_path: str (repo-relative)   │
│ line_number: int               │ ─────────────► │ line_number: int                 │
│ code_snippet: str              │ ─────────────► │ evidence.code_snippet: str       │
│ library: str                   │ ─────────────► │ library: str                     │
│ confidence: float              │ ─────────────► │ confidence: float                │
│ key_length: Optional[int]      │ ─────────────► │ key_size: Optional[int]          │
│ mode: Optional[str]            │ ─────────────► │ mode: Optional[str]              │
│ padding: Optional[str]         │ ─────────────► │ padding: Optional[str]           │
│ [MISSING in models.py]         │ ─────────────► │ language: str                    │
│ [MISSING in models.py]         │ ─────────────► │ evidence.detection_mechanism: str│
│ [MISSING in models.py]         │ ─────────────► │ operation: Optional[str]         │
│ [MISSING in models.py]         │ ─────────────► │ usage: Optional[str]             │
└────────────────────────────────┘                └──────────────────────────────────┘
```

### Unproduced & Missing Fields Audit
1. `language`: Derived in `scanner._determine_language` but dropped when creating `CryptoAsset`.
2. `primitive`: Currently output as `category` using non-standard strings (`symmetric_encryption` vs CycloneDX standard `symmetric-cipher`).
3. `evidence`: Currently flattened as `code_snippet`. Lacks structured metadata (`detection_mechanism`: 'ast'|'regex'|'pem_header', `matched_rule_id`).
4. `operation`: Currently uncaptured. Cannot distinguish between `AES` encryption, decryption, or key generation.
5. `usage`: Currently uncaptured. Cannot determine context (e.g. TLS stream vs file encryption).
6. Path Normalization: `file_path` currently stores local system absolute paths (`c:\Users\...\sample_python.py`), breaking cross-machine reproducibility. Must be relative to repository root.

---

## 5. Task 4 — Detection Quality Review & Findings

### 5.1 Quality Audit Matrix

| Issue Category | Description | Impact | Priority |
| :--- | :--- | :--- | :---: |
| **False Positives** | Regex rules scan full raw lines without filtering single-line (`//`, `#`) or multi-line (`/* */`, `"""`) comments. A commented line like `// Cipher.getInstance("AES/CBC/PKCS5Padding")` triggers a match. | Inflates asset count with commented-out dead code. | **P0** |
| **Path Normalization** | `CryptoAsset.file_path` contains OS-specific absolute paths. Matin's CBOM serializer and deduplicator cannot match assets across environments. | Breaks asset identity stability and CBOM generation. | **P0** |
| **Python AST Coverage Gap** | `PythonASTScanner` only checks PyCryptodome (`RSA.generate`, `AES.new`), `hashlib`, and basic `cryptography.hazmat.primitives.hashes`. It misses `cryptography.hazmat.primitives.ciphers` (`ciphers.Cipher`), `asymmetric.rsa`, `asymmetric.ec`, and `pbkdf2`. | Misses modern Python crypto usages (`cryptography` is the primary library used in production). | **P1** |
| **Java Key Size & API Gap** | Java regex only captures `Cipher`, `KeyPairGenerator`, and `MessageDigest`. Misses key size in initialization (`keyPairGen.initialize(2048)`), `KeyGenerator.init(256)`, `SecretKeySpec`, `Mac.getInstance("HmacSHA256")`, and `Signature.getInstance`. | `key_size` is null for all Java assets. | **P1** |
| **C/C++ OpenSSL API Gap** | C regex only captures direct `EVP_aes_128_cbc` function calls. Misses OpenSSL 3.0 `EVP_MAC`, `EVP_KDF`, `EVP_PKEY_Q_keygen`, `EVP_CipherInit_ex`, and `mbedTLS` / `libsodium` functions. | High false-negative rate on modern C/C++ repositories. | **P1** |
| **Dynamic Key Length AST** | In Python AST, `RSA.generate(key_size_var)` sets `key_length=None` and `confidence=0.75`, but doesn't track variable assignments within the same module scope. | Missing key size when variable is assigned nearby. | **P2** |
| **Duplicate Regex Hits** | In C and Java files, overlapping regex rules on the same line emit multiple duplicate `CryptoAsset` entries for a single API call. | Multiplies asset count in Matin's risk report. | **P0** |
| **Non-Deterministic ID** | `asset_id` uses random `uuid.uuid4().hex[:8]`. Scanning the exact same codebase twice produces different asset IDs. | Prevents diffing or tracking assets over time. | **P0** |

### 5.2 Prioritized Backlog (P0 / P1 / P2)

#### P0 — Critical (Blocks Reliable CryptoAsset Contract Generation)
1. **Deterministic `asset_id`**: Change `asset_id` generation to SHA-256 hash over `(file_path_relative, line_number, algorithm, library)`.
2. **Repo-Relative File Paths**: Normalize all `file_path` entries relative to repository root.
3. **Comment & String Suppression for Regex**: Strip single-line (`//`, `#`) and multi-line comments before regex rule evaluation.
4. **Multi-Language Intra-Line Deduplication**: Guarantee that only one highest-confidence asset is emitted per physical code invocation on a single line.

#### P1 — High (Important for POC Detection Quality & Demo Depth)
1. **Schema Extension**: Add `language`, `primitive`, `evidence` sub-object, and `operation` fields to `CryptoAsset`.
2. **Expanded Python AST Visitor**: Support `cryptography.hazmat` ciphers, asymmetric keys, signatures, and KDFs.
3. **Java Key Size & Mac Regexes**: Add rules for `KeyGenerator.init(N)`, `initialize(N)`, `Mac.getInstance`, and `Signature.getInstance`.
4. **C/C++ Modern OpenSSL & Header Rules**: Add OpenSSL 3.0 `EVP_PKEY_CTX` and algorithm family extraction.

#### P2 — Medium (Future Improvements & Optimization)
1. Constant propagation for local scope variable parameters in AST.
2. Context window capturing (fetch $\pm 2$ lines around detection for `evidence.context_snippet`).
3. Import statement tracking in Python AST to verify alias imports (e.g. `from Crypto.Cipher import AES as MyCipher`).

---

## 6. Task 5 — Realistic Cryptographic Test Fixture Matrix

To validate detection quality across realistic Enterprise codebases, the following fixture matrix defines the target sample files to be added in Phase 2:

| Language | Library / Target | Algorithm | Key Size / Mode / Parameters | Scenario / Code Pattern | Target Fixture File |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | `PyCryptodome` | RSA | 2048, 4096-bit | Static & dynamic key generation | `sample_python_extended.py` |
| **Python** | `PyCryptodome` | AES | CBC, GCM modes | Cipher instantiation with IV/Nonce | `sample_python_extended.py` |
| **Python** | `cryptography` | AES-GCM | 256-bit | Modern hazmat symmetric encryption | `sample_python_extended.py` |
| **Python** | `cryptography` | ECDSA | SECP256R1 (P-256) | Elliptic Curve signature generation | `sample_python_extended.py` |
| **Python** | `hashlib` | SHA-256, MD5 | Digest | Legacy vs modern hashing calls | `sample_python_extended.py` |
| **Java** | `javax.crypto` | AES | AES/GCM/NoPadding | Standard JCE cipher transformation | `sample_java_extended.java` |
| **Java** | `java.security` | RSA | 2048-bit `initialize(2048)` | `KeyPairGenerator` with explicit key size | `sample_java_extended.java` |
| **Java** | `java.security` | ECDSA | SHA256withECDSA | `Signature` engine instantiation | `sample_java_extended.java` |
| **Java** | `javax.crypto` | HmacSHA256 | 256-bit | `Mac.getInstance("HmacSHA256")` | `sample_java_extended.java` |
| **C** | `OpenSSL 1.1` | RSA | 2048-bit | `RSA_generate_key_ex` legacy API | `sample_c_extended.c` |
| **C** | `OpenSSL 3.0` | AES | 256-bit GCM | `EVP_aes_256_gcm()` & `EVP_CipherInit_ex` | `sample_c_extended.c` |
| **C** | `OpenSSL 3.0` | ECDH | prime256v1 | `EC_KEY_new_by_curve_name` / `EVP_PKEY` | `sample_c_extended.c` |
| **C++** | `OpenSSL / Wrapper` | SHA-1, SHA-256 | Digest | `EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)` | `sample_cpp_extended.cpp` |
| **PEM** | OpenSSL CLI | RSA / EC | 2048 / P-256 | PEM private keys & X.509 certs | `sample_keys_extended.pem` |

---

## 7. Task 6 — Rohan ↔ Matin Data & API Contract Guarantees

This section specifies the strict interface contract guaranteed by Rohan's scanner to Matin's analysis modules.

### 7.1 Contract Guarantees
1. **Field Non-Nullability Guarantee**:
   * Scanner **guarantees** that `asset_id`, `file_path`, `line_number`, `language`, `algorithm`, `primitive`, `library`, `confidence`, and `evidence` are **NEVER `None`** or empty.
2. **Nullable Fields Guarantee**:
   * `key_size`, `mode`, `padding`, `operation`, and `usage` **may be `None`** when statically unextractable. Matin's code must safely handle `None` for these specific optional attributes without raising `AttributeError` or `TypeError`.
3. **Evidence Integrity Guarantee**:
   * `evidence.code_snippet` is guaranteed to contain non-fabricated, original source code text matching `line_number` in `file_path`.
4. **Deterministic Identifier Guarantee**:
   * `asset_id` is guaranteed to be stable across repeated runs on unchanged source code.
5. **Deduplication Guarantee**:
   * Scanner guarantees that a single physical code invocation at `(file_path, line_number)` will result in **exactly one `CryptoAsset`**, selecting the highest-confidence finding when multiple detection rules match.
6. **Unknown Algorithm Fallback Guarantee**:
   * If a crypto API call is detected but the specific algorithm parameter is unrecognized, scanner emits `algorithm="UNKNOWN"`, `confidence=0.50`, preserving snippet evidence for Matin's fallback heuristics.

---

## 8. Task 7 — Target Architecture & Boundaries

```
                    ┌──────────────────────────────────────────┐
                    │       Target Repository Directory        │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │      File Discovery Engine (pathlib)     │
                    │   (Filters ext, respects ignore set)     │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │       Language Classifier Engine         │
                    └────────────────────┬─────────────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 │                       │                       │
                 ▼                       ▼                       ▼
      ┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
      │  Python AST Parser  │ │    Java Analyzer    │ │   C/C++ Analyzer    │
      │ (ast.NodeVisitor)   │ │    (Regex Rules)    │ │    (Regex Rules)    │
      └──────────┬──────────┘ └──────────┬──────────┘ └──────────┬──────────┘
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │      Regex Rules Engine & Normalizer     │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │       Deduplication & Asset Merger       │
                    └────────────────────┬─────────────────────┘
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │         Canonical CryptoAsset            │
                    └────────────────────┬─────────────────────┘
                                         │
        =========================│========================= CONTRACT BOUNDARY
                                         │
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │          Matin's Analysis Layer          │
                    │  ┌──────────────┬──────────────┬───────┐ │
                    │  │ CycloneDX 1.6│ Quantum Risk │  PQC  │ │
                    │  │     CBOM     │   Engine     │ Engine│ │
                    │  └──────────────┴──────────────┴───────┘ │
                    └──────────────────────────────────────────┘
```

### Boundary Responsibilities

#### Rohan's Area (Crypto Discovery & Scanner)
* Traversing repository filesystem structure safely and performantly.
* Detecting source code language by file extension and syntax structure.
* Parsing Abstract Syntax Trees (Python `ast`) and applying optimized Regex rules (Java, C/C++, PEM).
* Extracting precise file locations, line numbers, non-fabricated code snippets, algorithm names, primitives, key sizes, modes, and paddings.
* Normalizing findings and filtering duplicate detection events.
* Returning `List[CryptoAsset]`.

#### Matin's Area (Cryptographic Intelligence & Risk)
* Consuming `List[CryptoAsset]`.
* Assessing quantum vulnerability against Shor's algorithm (breaking RSA/ECC/DH) and Grover's algorithm (reducing AES key strength).
* Mapping cryptographic findings into official **CycloneDX 1.6 CBOM JSON** schemas.
* Calculating risk severity scores and defining PQC migration targets (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
* Serializing human-readable CLI report tables and CBOM artifacts.

---

## 9. Known Limitations

1. **Static Pre-Execution Bounds**: Indirect dynamic reflection in Java (`Class.forName(...)`), dynamic `getattr` in Python, or runtime configuration loading cannot be resolved statically.
2. **Binary Executables**: Inspection of compiled binaries (`.so`, `.dll`, `.exe`) is out of scope for the source code scanning engine.
3. **Multi-Line Syntax Trees in Non-Python Languages**: Java and C/C++ analysis currently relies on regex pattern matching over individual line strings, limiting context across multi-line function calls.

---

## 10. Implementation Roadmap & Order of Work

### Phase 1: Design & Audit (Today — Complete)
* Complete codebase audit of `26164/src/ecdat/`.
* Define `CryptoAsset` canonical output schema.
* Document Rohan $\leftrightarrow$ Matin data contract and architecture.
* Produce `26164/docs/CRYPTO_SCANNER_DESIGN.md`.
* Run and verify existing 26164 test suite (8/8 tests passing).

### Phase 2: Core Refactoring & P0 Fixes (Next Step)
* Upgrade `CryptoAsset` model in `models.py` to match canonical contract (`language`, `primitive`, `evidence` dict, `operation`).
* Implement deterministic SHA-256 `asset_id` generation.
* Implement repository-relative path normalization.
* Add comment/docstring stripping before regex evaluation.
* Implement intra-line asset deduplication across all languages.

### Phase 3: P1 Feature Expansion & Fixture Matrix
* Extend Python AST visitor (`ast_parser.py`) for `cryptography.hazmat` modules.
* Add Java key length, MAC, and Signature regex rules.
* Add modern OpenSSL 3.0 C/C++ regex rules.
* Create extended test fixtures matrix in `26164/tests/fixtures/`.
* Expand test suite in `26164/tests/test_scanner.py`.

---

## 11. Test Suite & Codebase Validation Results

The baseline test suite was executed without modifying production or test code.

### Execution Command
```bash
python 26164/tests/run_tests.py
```

### Test Results Summary
* **Total Test Count**: 8
* **Passed**: 8
* **Failed**: 0
* **Execution Time**: 0.084 seconds
* **Files Modified**: None
* **Files Created**: `26164/docs/CRYPTO_SCANNER_DESIGN.md`

### Test Breakdown Table
| Test Name | Focus Area | Result |
| :--- | :--- | :---: |
| `test_01_file_discovery` | File discovery and directory exclusion | **PASSED** |
| `test_02_python_ast_and_regex` | Python AST & regex detection (RSA, AES, SHA, MD5) | **PASSED** |
| `test_03_java_detection` | Java Cipher transformation parsing | **PASSED** |
| `test_04_c_detection` | C OpenSSL EVP pattern matching | **PASSED** |
| `test_05_pem_detection` | PEM key header matching | **PASSED** |
| `test_06_line_numbers_and_snippets` | Line tracking & code snippet extraction | **PASSED** |
| `test_07_clean_code_false_positives` | Clean code zero false-positive check | **PASSED** |
| `test_08_full_directory_scan` | Full directory scan & `CryptoAsset` serialization | **PASSED** |
