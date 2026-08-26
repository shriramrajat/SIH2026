# SIH 2026

Technical POC repository for our active Smart India Hackathon 2026 problem statements.

## Team

| Member | GitHub | Role | Primary Responsibility |
|---|---|---|---|
| Rajat | `shriramrajat` | Team Leader | Architecture, technical decisions, integration, coordination, final presentation |
| Rohan | `rskusalkar78` | Core Developer — 26164 | ECDAT/Crypto Scanner core development |
| Matin | `shaikhmatin723-blip` | Core Developer — 26164 | Scanner validation, testing, detection accuracy |
| Ashutosh | `AshutoshMashitkar` | Supporting Developer + Documentation | Development support, testing, fixtures, technical documentation |
| Shruti | — | PPT + Documentation | PPT, documentation, diagrams and visuals |
| Arya | — | PPT + Documentation | PPT, documentation, demo flow and presentation preparation |
| Everyone | — | Presentation & Q&A | Understand both PSs and participate in final presentation |

---

## Active Problem Statements

### PS 26155 — Network Device Security Compliance

**Full title:** AI-Driven Multi-Vendor Network Security Compliance Auditor

**Owner:** Rajat

**Status:** Active — Flagship

**Current implementation:**
- Cisco IOS/IOS-XE and Juniper JunOS parsers
- Vendor-neutral normalization model
- Deterministic compliance engine
- 4 controls: SSH-001, TLN-001, EXEC-001, PWD-001
- **229 tests passing**

**See:** [`26155/README.md`](26155/README.md) | [`26155/docs/`](26155/docs/)

---

### PS 26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

**Full title:** Enterprise Cryptographic Discovery & Analysis Tool

**Owners:** Rohan (scanner core), Matin (validation, testing)

**Status:** Active — Secondary

**Current implementation:**
- Recursive source-file discovery with directory exclusion
- Python AST-based detection (`ast_parser.py`)
- Regex-based detection for Python, Java, C/C++, PEM files
- Comment stripping (Python `#`, Java/C `//` and `/* */`)
- `CryptoAsset` model with structured `Evidence`
- Deterministic SHA-256 asset IDs
- Repo-relative normalised file paths
- **13 tests passing**

**See:** [`26164/README.md`](26164/README.md) | [`26164/Docs/`](26164/Docs/)

---

## Dropped Problem Statements

### PS 26100 — AI-Powered Integrated Bid Compliance Verification Platform
**Status:** Dropped

**Reason:** The team can pursue a maximum of two PS. PS 26155 + PS 26164 provide a stronger complementary cybersecurity-focused portfolio and better technical coherence.

### PS 26103 — Web-Based Integrated Project Monitoring Platform
**Status:** Dropped

**Reason:** Team can pursue a maximum of two PS. PS 26103 has the least technical progress and lowest strategic differentiation.

---

## Development Strategy

We are building **technical Proofs of Concept first**, not production systems.

The objective is to prove the hardest and most important technical ideas.

`Understand → Research → Define → Design → Implement → Test → Measure → Review → Improve`

## Git Workflow

Do not work directly on `main`.

`POC branch → Feature branch → Implementation → Testing → Commit → Push → Pull Request → Review → Merge`

## Protected Branches

- `main`
- `poc/26155`
- `poc/26164`

Pull requests and review are required before merging into protected branches.

## Engineering Principles

We prioritize:

- Correctness
- Security
- Reproducibility
- Clean architecture
- Testing
- Evidence-backed results
- Realistic scope
- Technical differentiation

We avoid:

- Unnecessary complexity
- Fake AI features
- Premature optimization
- Scope creep
- Hardcoded secrets
- Unnecessary dependencies
- Blindly copying AI-generated code

---

## Implementation Status (main branch)

| PS | Status | Tests |
|---|---|---|
| **26155** | Compliance engine + 4 controls (SSH-001, TLN-001, EXEC-001, PWD-001) | **229 passing** |
| **26164** | Scanner engine + AST + regex + comment stripping + evidence model | **13 passing** |
| 26100 | Dropped | — |
| 26103 | Dropped | — |
