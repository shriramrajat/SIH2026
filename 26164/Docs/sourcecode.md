# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Day 1: Source Code Cryptographic Discovery Strategy (PS 26164)

---

### 1. Detection Strategy Overview

To reliably detect cryptography in source code without missing subtle usages or flooding results with false positives, ECDAT uses a **Dual-Engine Detection Pipeline**:

```
Source File
   ├──> Pass 1: Fast Regex Pattern Scanning (Imports, API function names, String constants)
   └──> Pass 2: AST Structural Analysis (Parameter extraction: key size, cipher mode, padding)
```

---

### 2. Dual-Engine Architecture

#### Engine A: Fast Regex Pattern Engine
* **Purpose**: Broad coverage across multiple languages (`.py`, `.java`, `.c`, `.cpp`).
* **Targets**:
  * Import/Include directives: `import Crypto`, `from cryptography.hazmat`, `import java.security.*`, `#include <openssl/rsa.h>`
  * Primitive instantiations: `Cipher.getInstance("AES/CBC/PKCS5Padding")`, `AES.new(...)`, `hashlib.sha256()`
  * Hardcoded key/PEM headers: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`

#### Engine B: AST (Abstract Syntax Tree) Engine
* **Purpose**: Deep parameter and context extraction (Python & Java).
* **Targets**:
  * Extracts exact keyword/positional arguments:
    * `RSA.generate(2048)` -> Extracts `algorithm="RSA"`, `key_length=2048`
    * `AES.new(key, AES.MODE_CBC)` -> Extracts `algorithm="AES"`, `mode="CBC"`
    * `hashes.SHA1()` -> Extracts `algorithm="SHA-1"`
  * Assigns confidence scores based on structural certainty:
    * Full AST match with static parameters: `Confidence = 0.95`
    * Regex API invocation match without static parameters: `Confidence = 0.80`
    * Generic import directive without explicit call site: `Confidence = 0.60`

---

### 3. Detection Rule Specification Table

| Language | Target Library / Module | Regex / AST Pattern | Extracted Algorithm | Extracted Metadata |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | `hashlib` | `hashlib\.(md5\|sha1\|sha256\|sha512)\(` | MD5, SHA-1, SHA-256, SHA-512 | Hash function type |
| **Python** | `PyCryptodome` | `RSA\.generate\(\s*(\d+)\s*\)` | RSA | Key length (e.g. 1024, 2048, 4096) |
| **Python** | `cryptography` | `ciphers\.modes\.(CBC\|GCM\|ECB)` | AES | Cipher Mode |
| **Java** | `javax.crypto` | `Cipher\.getInstance\("([^"]+)"\)` | AES, RSA, DES | Transformation string (e.g. `AES/GCM/NoPadding`) |
| **Java** | `java.security` | `KeyPairGenerator\.getInstance\("([^"]+)"\)` | RSA, EC, DSA | Key Algorithm |
| **C / C++** | `OpenSSL` | `RSA_generate_key_ex\(` | RSA | OpenSSL API call |
| **C / C++** | `OpenSSL` | `EVP_aes_(\d+)_(cbc\|gcm)` | AES | Key length (128/256) & mode |
