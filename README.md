# SIH 2026

Technical POC repository for our shortlisted Smart India Hackathon 2026 problem statements.

## Team

| Member | GitHub | Role |
|---|---|---|
| Rajat | `shriramrajat` | Team Lead / Technical Lead |
| Rohan | `rskusalkar78` | PS 26164 Owner |
| Matin | `shaikhmatin723-blip` | PS 26100 Owner |
| Ashutosh | `AshutoshMashitkar` | Standby / Support |

## Shortlisted Problem Statements

### PS 26155

**AI-Driven Multi-Vendor Network Security Compliance Auditor**

**Owner:** Rajat

**Branch:** `poc/26155`

**Focus:**
- Multi-vendor configuration analysis
- Vendor-neutral normalization
- Security compliance
- AI-assisted configuration adaptation
- Remediation
- Reporting

---

### PS 26164

**Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**

**Owner:** Rohan

**Branch:** `poc/26164`

**Focus:**
- Cryptographic artefact discovery
- Source-code scanning
- CBOM generation
- Quantum risk assessment
- PQC migration recommendations

**Initial POC flow:**

`Source Repository → Crypto Scanner → Crypto Artefacts → Structured CBOM-style Output`

---

### PS 26100

**AI-Powered Integrated Bid Compliance Verification Platform for GeM Procurement**

**Owner:** Matin

**Branch:** `poc/26100`

**Focus:**
- Tender requirement extraction
- Bidder evidence extraction
- Requirement matching
- Compliance verification
- Evidence-backed results
- Reporting

**Initial POC flow:**

`Tender → Requirements → Bid Document → Evidence → Compliance Result`

---

### PS 26103

**Web-Based Integrated Project Monitoring Platform**

**Owner:** Rajat

**Support:** Ashutosh

**Branch:** `poc/26103`

**Focus:**
- Project monitoring
- Tasks
- Milestones
- Progress
- Dependencies
- Risk detection
- Alerts

---

## Development Strategy

We are building **technical Proofs of Concept first**, not four complete production systems.

The objective is to prove the hardest and most important technical ideas.

Our general development cycle is:

`Understand → Research → Define → Design → Implement → Test → Measure → Review → Improve`

## Git Workflow

Do not work directly on `main`.

Use:

`POC branch → Feature branch → Implementation → Testing → Commit → Push → Pull Request → Review → Merge`

Examples:

- `feature/crypto-scanner`
- `feature/requirement-extraction`
- `feature/network-parser`
- `feature/project-risk-engine`

## Protected Branches

The following branches are protected:

- `main`
- `poc/26155`
- `poc/26164`
- `poc/26100`
- `poc/26103`

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

## Repository Documentation

Detailed problem-statement documentation is maintained under:

`Projects/SIH/`

The CareerOS repository contains the broader SIH planning and execution documentation.

## Current Status

## Active Problem Statements

### PS 26155
AI-Driven Multi-Vendor Network Security Compliance Auditor
**Status:** Active — Flagship

### PS 26164
Enterprise Cryptographic Discovery & Analysis Tool
**Status:** Active

### PS 26100
AI-Powered Integrated Bid Compliance Verification Platform
**Status:** Active — Secondary

## Dropped Problem Statements

### PS 26103
Web-Based Integrated Project Monitoring Platform
**Status:** Dropped

**Reason:** Team can pursue a maximum of two PS for the final SIH submission. PS 26103 has the least technical progress and lowest strategic differentiation, so development is discontinued.