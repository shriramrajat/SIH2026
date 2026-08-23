# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Day 1: Quantum Risk Scoring & PQC Migration Engine (PS 26164)

---

### 1. Quantum Vulnerability Mechanics

Quantum computers running **Shor's Algorithm** can solve prime factorization (RSA) and discrete logarithms (ECC, ECDSA, ECDH, DH) in polynomial time, rendering all classical asymmetric public-key cryptography insecure.

Quantum computers running **Grover's Algorithm** provide a quadratic speedup for unstructured brute-force searches, effectively halving the symmetric key security margin (e.g., AES-128 drops to 64-bit effective security; AES-256 drops to 128-bit effective security).

---

### 2. Quantum Risk Severity Rating Matrix

| Severity Level | Criteria | Examples | Action Required |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Asymmetric algorithm broken by Shor's algorithm. | RSA (all key sizes), ECC (P-256, Ed25519), DH, DSA | Immediate migration planning to PQC (ML-KEM / ML-DSA). |
| **HIGH** | Legacy / Broken classical algorithm (vulnerable to classical attacks). | MD5, SHA-1, DES, 3DES, RC4 | Immediate replacement with secure classical primitives (SHA-256/3, AES-GCM). |
| **MEDIUM** | Symmetric algorithm vulnerable to Grover's algorithm reduction. | AES-128, 3-Key Triple DES | Upgrade key size to 256 bits (AES-256). |
| **SAFE / PQC** | Quantum-resistant algorithms & NIST-standardized PQC primitives. | AES-256, SHA-3, ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+) | Compliant with Post-Quantum Standards. |

---

### 3. NIST PQC Standards & Migration Recommendation Mapping

In August 2024, NIST released the finalized Post-Quantum Cryptography standards:
* **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (**ML-KEM**, derived from CRYSTALS-Kyber).
* **FIPS 204**: Module-Lattice-Based Digital Signature Algorithm (**ML-DSA**, derived from CRYSTALS-Dilithium).
* **FIPS 205**: Stateless Hash-Based Digital Signature Algorithm (**SLH-DSA**, derived from SPHINCS+).

#### ECDAT Automated PQC Recommendation Engine Rules:

```
[RSA-2048 / RSA-4096 Key Exchange]   ──> Replace with ──> ML-KEM-768 (FIPS 203) or Hybrid (ECDH + ML-KEM)
[ECDSA P-256 / Ed25519 Signature]   ──> Replace with ──> ML-DSA-65 (FIPS 204)
[High-Security Digital Signatures]   ──> Replace with ──> SLH-DSA-SHA2-128s (FIPS 205)
[AES-128 Encryption]                ──> Upgrade to   ──> AES-256-GCM
[MD5 / SHA-1 Hashing]               ──> Upgrade to   ──> SHA-256 / SHA-3-256
```
