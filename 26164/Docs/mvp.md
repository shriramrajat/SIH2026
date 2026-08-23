# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Day 1: Product Definition, Research, & Scope (PS 26164)

---

### 1. Understanding PS 26164
Modern enterprises rely on hundreds of cryptographic implementations embedded across legacy source code, modern applications, dependencies, and infrastructure. With the rapid advance of quantum computing and NIST's release of Post-Quantum Cryptography (PQC) standards (FIPS 203, FIPS 204, FIPS 205 in August 2024), organizations face an urgent mandate: **Catalog all cryptographic assets, evaluate quantum risk exposure, and plan migration to quantum-resistant algorithms.**

**ECDAT Core Goal**: Provide automated cryptographic discovery, generate standardized Cryptographic Bill of Materials (CBOM), evaluate quantum vulnerability, and offer concrete PQC migration paths.

---

### 2. Research on Existing Tools & Industry Landscape
| Tool | Strengths | Weaknesses / Gaps |
| :--- | :--- | :--- |
| **Syft / Trivy** | Excellent Software Bill of Materials (SBOM) for packages. | Ignores source-level cryptography, algorithm parameters, key lengths, and usage context. |
| **IBM CBOM Kit** | Standardized CBOM representation. | Heavy enterprise setup, complex configuration, high barrier for quick repo audit. |
| **SonarQube / Semgrep** | Good SAST security rules for hardcoded keys / weak algorithms. | Lacks CBOM export, quantum risk scoring engine, and PQC migration mapping. |

---

### 3. Key Gap & ECDAT POC Differentiation
1. **Context-Aware Crypto Discovery**: Detection beyond package names — pinpointing exact algorithm, key length, mode of operation, and API invocation line in source code.
2. **CycloneDX 1.6 CBOM Native Output**: Exporting industry-standard CBOM JSON formats tailored specifically for cryptographic auditing.
3. **Automated Quantum Risk Rating**: Instant categorization into Post-Quantum Vulnerable (Shor's algorithm targets), Weak Classical, and Quantum-Resistant assets.
4. **Actionable PQC Guidance**: Direct migration recommendation mapping deprecated algorithms (e.g., RSA-2048, ECDSA-P256) to NIST PQC standards (e.g., ML-KEM-768, ML-DSA-65).
5. **Zero-Dependency Core CLI**: Portable Python-based engine requiring no external server or commercial daemon.

---

### 4. Defined MVP / POC Scope Boundaries

#### In-Scope for Initial POC:
* **Target Domain**: Source Code Cryptographic Discovery (Python, Java, C/C++ primitives).
* **Detection Targets**:
  * Asymmetric: RSA, ECC (ECDSA, ECDH), Diffie-Hellman (DH).
  * Symmetric: AES (CBC, GCM, ECB modes).
  * Hashing / Digest: SHA-256, SHA-512, SHA-1, MD5.
  * Libraries: PyCryptodome, `cryptography`, `hashlib`, `java.security`, `javax.crypto`, OpenSSL API calls.
* **Output Capabilities**: Structured Asset JSON, CycloneDX 1.6 CBOM JSON, Terminal Summary report with Quantum Risk scores.

#### Out-of-Scope for Initial POC (Deferred to Future Phases):
* Live TLS network traffic scanning.
* Active certificate authority / LDAP polling.
* Live container image filesystem inspection.
* Full-scale web dashboard or multi-tenant database.
* Obfuscated binary reverse-engineering.

---

### 5. Risks & Open Technical Questions

#### Technical Risks:
* **Dynamic / Indirect Crypto Loading**: Dynamic reflection in Java (`Class.forName(...)`) or Python (`getattr(...)`) may evade static pattern matching.
  * *Mitigation*: Flag indirect/dynamic crypto calls with `LOW` confidence and a `NEEDS_REVIEW` tag.
* **Key Length Inference**: Static code analysis cannot always resolve runtime variable key lengths (`RSA.generate(keysize_var)`).
  * *Mitigation*: Fall back to default algorithm risk profiles when parameters cannot be statically resolved.

#### Open Questions for Team Lead (Rajat):
1. Should the initial scanner CLI strictly produce CycloneDX 1.6 JSON, or also a simplified human-readable CLI summary table?
2. Are Python, Java, and C/C++ sufficient language targets for the Day 2 & Day 3 POC demonstration?

---

### 6. Recommended Day 2 Starting Point
* Create the repository folder structure under `26164/src/`.
* Implement the core static detection engine (`scanner.py` and `rules.py`) supporting regex and Python AST parsing.
* Create a suite of synthetic test vector files containing valid and vulnerable crypto snippets to verify detection accuracy.
