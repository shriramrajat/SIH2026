# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
# Day 1 Master Technical Specification & Architecture Document
**Project Code**: PS 26164 | **Owner**: Rohan (rskusalkar78) | **Tech Lead**: Rajat (shriramrajat)
**Branch**: `poc/26164`

---

## Executive Summary & Day 1 Checklist Verification

| # | Checklist Item | Status | Document Link |
| :--- | :--- | :---: | :--- |
| 1 | Understand PS 26164 properly | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |
| 2 | Research existing CBOM/crypto-scanning tools | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |
| 3 | Find the gap/differentiation for our POC | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |
| 4 | Define MVP / must-have features | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |
| 5 | Design the basic system architecture | Completed | [architecture.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/architecture.md) |
| 6 | Decide how we'll detect crypto in source code | Completed | [sourcecode.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/sourcecode.md) |
| 7 | Design the CBOM/data structure | Completed | [datastructure.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/datastructure.md) |
| 8 | Design the quantum-risk scoring approach | Completed | [riskscoring.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/riskscoring.md) |
| 9 | Research PQC + migration recommendations | Completed | [riskscoring.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/riskscoring.md) |
| 10 | Finalize a realistic tech stack | Completed | [architecture.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/architecture.md) |
| 11 | Create a Day-1 technical document | Completed | [day1_technical_spec.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/day1_technical_spec.md) |
| 12 | List risks + open questions | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |
| 13 | Give recommended Day-2 starting point | Completed | [mvp.md](file:///c:/Users/ROHAN/Desktop/SIH2026/26164/Docs/mvp.md) |

---

## 1. Problem Statement Understanding (PS 26164)
Organizations need to discover and catalogue cryptographic artifacts across source code, dependencies, containers, certificates, and infrastructure to prepare for Post-Quantum Cryptography (PQC) migration.
For our SIH POC, we focus specifically on **Source Code Cryptographic Discovery**, creating a light, accurate, zero-dependency scanner that outputs standardized CycloneDX 1.6 CBOM format with quantum risk assessment.

---

## 2. Competitive Landscape & Gap Analysis
* **Syft / Trivy**: Packages & SBOM focused; zero cryptographic parameter inspection.
* **IBM CBOM Kit**: Enterprise heavy; difficult setup for rapid developer repo auditing.
* **SonarQube / Semgrep**: Security rules only; lacks native CBOM output and quantum risk scoring.
* **ECDAT Differentiation**: Lightweight, context-aware source code scanning + CycloneDX 1.6 CBOM + Quantum Risk Severity Score + NIST PQC Migration recommendations out of the box.

---

## 3. System Architecture & Tech Stack
* **Language**: Python 3.11+
* **Core Parsing**: Standard library regex (`re`) + Python Abstract Syntax Tree (`ast`).
* **Data Validation & Formatting**: Pydantic / dataclasses + `rich` CLI output formatting.
* **Pipeline Flow**: File Scanner -> Dual-Engine Parser (Regex + AST) -> Normalizer -> Quantum Risk Classifier -> PQC Migration Mapping -> CBOM JSON & CLI Summary.

---

## 4. Quantum Risk Matrix & NIST PQC Alignment
* **CRITICAL**: RSA, ECC, DH, DSA (Vulnerable to Shor's Algorithm) -> Recommend **ML-KEM-768** (FIPS 203) / **ML-DSA-65** (FIPS 204).
* **HIGH**: MD5, SHA-1, DES (Broken Classically) -> Recommend **SHA-256** / **SHA-3**.
* **MEDIUM**: AES-128 (Reduced by Grover's Algorithm) -> Recommend **AES-256-GCM**.
* **SAFE**: AES-256, SHA-3, PQC Primitives.

---

## 5. Day 2 Plan & Starting Point
* Create Python package structure under `26164/src/ecdat/`.
* Implement `rules.py` containing regex patterns & AST visitor definitions for Python, Java, and C/C++.
* Implement `scanner.py` engine and unit tests in `tests/test_scanner.py` verifying test vectors.
