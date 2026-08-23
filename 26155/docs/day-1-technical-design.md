# PS 26155 — Day 1 Technical Design

## 1. Objective

Build a modular Proof of Concept (POC) for analyzing network-device configurations from multiple vendors and evaluating their security compliance.

The system must produce explainable, evidence-backed compliance results.

---

## 2. High-Level Architecture

    Configuration File
            ↓
        Ingestion
            ↓
      Vendor Detection
            ↓
        Vendor Parser
            ↓
    Vendor-Neutral Normalization
            ↓
      Compliance Engine
            ↓
      Evidence Collection
            ↓
      Compliance Result
            ↓
      Remediation / Report

---

## 3. Proposed Repository Structure

    26155/
    ├── README.md
    ├── docs/
    │   ├── problem-understanding.md
    │   └── day-1-technical-design.md
    │
    ├── src/
    │   ├── ingestion/
    │   ├── parsers/
    │   ├── normalization/
    │   ├── compliance/
    │   ├── evidence/
    │   ├── remediation/
    │   └── reports/
    │
    └── tests/
        ├── fixtures/
        ├── integration/
        └── unit/

The modules are intentionally separated so vendor-specific parsing does not leak into the compliance engine.

---

## 4. Module Responsibilities

### Ingestion

Responsible for:

- Accepting configuration files
- Validating file input
- Reading configuration content
- Passing configuration to the appropriate parser

### Vendor Detection

Responsible for identifying the configuration vendor.

Initial POC:

- Cisco
- One additional vendor

Vendor detection should be replaceable without modifying the compliance engine.

### Vendor Parsers

Each vendor should have its own parser.

Example:

    Cisco Parser
          ↓
    Cisco-specific representation

    Vendor B Parser
          ↓
    Vendor B-specific representation

Parsers should focus only on understanding vendor syntax.

### Normalization

Converts vendor-specific representations into a common model.

Example:

    {
      "control": "secure_management_protocol",
      "state": "enabled",
      "protocol": "ssh",
      "version": 2
    }

The compliance engine consumes this normalized model instead of raw vendor configuration.

### Compliance Engine

Evaluates normalized security states against deterministic compliance rules.

Example:

    Normalized State
           ↓
      Security Rule
           ↓
    COMPLIANT / NON_COMPLIANT

Compliance rules should remain vendor-neutral wherever possible.

### Evidence

Every compliance decision should retain evidence from the original configuration.

Evidence should include:

- Configuration line or section
- Normalized value
- Rule/control evaluated
- Result

### Remediation

Generates a recommended corrective action for non-compliant controls.

Remediation must not automatically modify the original configuration.

### Reports

Converts compliance results into a human-readable output.

Initial POC can use structured JSON output before adding a web interface.

---

## 5. Core Data Flow

    Raw Configuration
            ↓
         Parser
            ↓
    Parsed Vendor Model
            ↓
    Normalized Security Model
            ↓
      Compliance Rules
            ↓
         Evidence
            ↓
    Compliance Result
            ↓
        Remediation

---

## 6. Compliance Result Model

Initial result states:

- COMPLIANT
- NON_COMPLIANT
- PARTIALLY_COMPLIANT
- NOT_APPLICABLE
- NEEDS_REVIEW

A result should contain at minimum:

    {
      "control_id": "SSH-001",
      "control_name": "SSH Version",
      "status": "NON_COMPLIANT",
      "severity": "HIGH",
      "evidence": [],
      "explanation": "",
      "remediation": ""
    }

---

## 7. AI Integration

AI should assist the deterministic pipeline rather than replace it.

AI may assist with:

- Configuration interpretation
- Semantic mapping
- Vendor-specific concept identification
- Remediation explanation

AI should not independently make final compliance decisions when deterministic evidence is available.

The compliance engine remains responsible for the final decision.

---

## 8. Initial Security Controls

The initial POC should evaluate a limited set of controls, such as:

- SSH configuration
- Telnet usage
- Password/security policy
- Privileged access
- Logging configuration
- Access control configuration
- Unused/insecure services

The exact controls will be finalized after analyzing representative configuration samples.

---

## 9. Design Principles

The implementation should prioritize:

- Vendor neutrality
- Explainability
- Evidence-backed decisions
- Modular architecture
- Testability
- Security
- Reproducibility

Avoid:

- Vendor-specific logic inside compliance rules
- Blind LLM-based compliance decisions
- Autonomous configuration modification
- Premature microservices
- Unnecessary dependencies
- Scope creep

---

## 10. Day 1 Decision

For the initial POC, use a modular application architecture.

Do not introduce microservices unless a concrete requirement appears.

The first implementation milestone is:

    Cisco Configuration
            ↓
       Cisco Parser
            ↓
     Normalized Model
            ↓
      Compliance Rules
            ↓
    Evidence-backed Result

Once this pipeline works reliably, the second vendor can be added through the same parser and normalization interfaces.