# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Source Code Cryptographic Discovery Engine (POC Phase)

**PS 26164** | **Owner**: Rohan (rskusalkar78) | **Tech Lead**: Rajat (shriramrajat) | **Branch**: `poc/26164`

---

### Overview
ECDAT is a zero-dependency, context-aware static cryptographic asset discovery engine designed to scan source repositories for cryptographic algorithms, key lengths, cipher modes, and PEM key/certificate headers.

---

### What Currently Works
* **File Discovery**: Recursively traverses source directories while automatically skipping `.git`, `__pycache__`, `venv`, `node_modules`, `build`, and `dist`.
* **Multi-Language Support**:
  * **Python** (`.py`): Dual-pass regex and Python AST (Abstract Syntax Tree) parameter extraction.
  * **Java** (`.java`): Regex pattern scanning and dynamic `Cipher.getInstance()` transformation string parsing.
  * **C / C++** (`.c`, `.cpp`, `.h`, `.hpp`): OpenSSL API pattern scanning and parameter extraction.
  * **Key / Certificate Files** (`.pem`, `.crt`, `.key`): PEM header marker identification.
* **Crypto Algorithms Detected**:
  * **Asymmetric**: RSA, ECC (ECDSA, ECDH), Diffie-Hellman (DH), DSA.
  * **Symmetric**: AES (CBC, GCM, ECB modes).
  * **Hashing / Digest**: MD5, SHA-1, SHA-256, SHA-512.
  * **Libraries**: `hashlib`, `PyCryptodome`, `cryptography`, `java.security`, `javax.crypto`, `OpenSSL`.
* **Precision Confidence Scoring**:
  * `0.95`: AST structural match with statically resolved parameters (`RSA.generate(2048)`).
  * `0.90`: PEM Header markers (`-----BEGIN RSA PRIVATE KEY-----`).
  * `0.80`: Standard Regex API invocation match.
  * `0.75`: AST structural match with dynamic/unresolved parameters (`RSA.generate(var)`).
* **Line Number & Snippet Verification**: Every detected asset contains line numbers and actual non-fabricated source code snippets.

---

### How to Run Tests
Run the standard library test runner:
```bash
python 26164/tests/run_tests.py
```
Or if `pytest` is installed in your environment:
```bash
python -m pytest 26164/tests/ -v
```

---

### How to Use the Scanner Programmatically
```python
from pathlib import Path
from ecdat.scanner import Scanner

scanner = Scanner()
assets = scanner.scan(Path("26164/tests/fixtures"))

for asset in assets:
    print(f"[{asset.confidence}] {asset.algorithm} ({asset.category}) at {asset.file_path}:{asset.line_number}")
    print(f"  Snippet: {asset.code_snippet}")
```

---

### Current Limitations
1. **Dynamic Reflection**: Indirect reflect-based calls in Java (`Class.forName(...)`) or dynamic `getattr` calls in Python are not symbolically executed.
2. **Binary Inspection**: Binary executable reverse engineering is out of scope for the static POC discovery engine.
