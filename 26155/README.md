# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

## Problem Statement

| Field        | Value                                              |
|--------------|----------------------------------------------------|
| **PS ID**    | SIH 26155                                          |
| **Org**      | National Technical Research Organisation (NTRO)    |
| **Category** | Software                                           |
| **Theme**    | Blockchain & Cybersecurity                         |

---

## Current Architecture

```
Raw configuration
       ↓
Vendor detection
       ↓
Vendor parser
       ↓
NormalizedConfig
       ↓
Compliance Engine
       ↓
Compliance Rules
       ↓
Evidence + Remediation
```

### Important Architectural Principle
Compliance rules consume `NormalizedConfig`. They must not parse raw configuration directly. AI/LLM is NOT currently part of deterministic compliance evaluation.

---

## Supported Vendors

- Cisco IOS / IOS-XE
- Juniper JunOS

---

## Current Implementation

- Cisco parser
- Juniper parser
- Vendor-neutral normalization model
- Deterministic compliance engine
- `ComplianceRule` abstraction
- Shared `ComplianceResult` builder
- Evidence model
- Remediation model

---

## Current Controls

- SSH-001 — SSH version must be version 2
- TLN-001 — Telnet management must be disabled
- EXEC-001 — VTY idle session timeout must be configured

---

## Testing

- Current full suite: 200 tests passing

To run tests from the repository root:
```bash
python -m pytest 26155/tests/ -q
```

---

## Current Limitations

- **Heuristic Detection:** Vendor detection is heuristic. Unusual or heavily stripped configs may yield "unknown".
- **Parsing Scope:** Parsers extract hostname, top-level directives, and block sections relevant for the current compliance rules, but do not fully parse every command of the vendor CLI.
- **Reporting & UI:** Remediation and evidence are generated programmatically, but no UI or AI reporting layer exists yet.
