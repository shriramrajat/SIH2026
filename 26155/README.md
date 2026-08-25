# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

## Problem Statement

| Field | Value |
|---|---|
| **PS ID** | SIH 26155 |
| **Org** | National Technical Research Organisation (NTRO) |
| **Category** | Software |
| **Theme** | Blockchain & Cybersecurity |

---

## Current Architecture

```
Raw configuration
       ↓
Vendor detection
       ↓
Vendor parser (Cisco or Juniper)
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

Compliance rules consume `NormalizedConfig`. They must not parse raw configuration directly. AI/LLM is **not** currently part of deterministic compliance evaluation.

---

## Supported Vendors

| Vendor | Parser | Controls evaluated |
|---|---|---|
| Cisco IOS / IOS-XE | `src/parsers/cisco.py` | SSH-001, TLN-001, EXEC-001, PWD-001 |
| Juniper JunOS | `src/parsers/juniper.py` | SSH-001, TLN-001, EXEC-001, PWD-001 |
| Others | — | Returns `NOT_APPLICABLE` for all controls |

---

## Current Implementation

| Component | Status |
|---|---|
| Ingestion (`loader.py`, `detector.py`) | ✅ Implemented |
| Cisco IOS / IOS-XE parser | ✅ Implemented |
| Juniper JunOS parser | ✅ Implemented |
| Vendor-neutral normalization model | ✅ Implemented |
| Compliance engine (`audit()`) | ✅ Implemented |
| `ComplianceResult` / `Evidence` / `Remediation` model | ✅ Implemented |
| SSH-001 — SSH Protocol Version | ✅ Implemented |
| TLN-001 — Telnet Must Be Disabled | ✅ Implemented |
| EXEC-001 — VTY Idle Session Timeout | ✅ Implemented |
| PWD-001 — Privileged Password Hashing | ✅ Implemented |
| Reporting / output layer | ❌ Not implemented |
| Web interface / API | ❌ Not implemented |
| AI-assisted normalization | ❌ Not implemented |

---

## Current Controls

| Control | Name | Severity | Vendors |
|---|---|---|---|
| **SSH-001** | SSH Protocol Version Must Be 2 | HIGH | Cisco, Juniper |
| **TLN-001** | Telnet Must Be Disabled | CRITICAL | Cisco, Juniper |
| **EXEC-001** | VTY Idle Session Timeout Must Be Configured | HIGH | Cisco, Juniper |
| **PWD-001** | Privileged Exec / Root Password Must Use Strong Hashing | HIGH | Cisco, Juniper |

---

## Testing

**Current full suite: 229 tests passing.**

To run tests from the repository root:

```bash
python -m pytest 26155/tests/unit/ -q
```

Expected output:

```
229 passed in ~0.6s
```

---

## Current Limitations

- **Heuristic detection:** Vendor detection is heuristic. Unusual or heavily stripped Cisco configs may yield `"unknown"`. Juniper is not detected automatically — the Juniper parser must be called directly.
- **Parsing scope:** Parsers extract hostname, top-level directives, and block sections relevant for compliance rules. They do not implement full vendor CLI grammars.
- **Juniper parser flattening:** Items nested more than one level deep inside JunOS blocks are captured under the enclosing top-level section. Rules must account for this.
- **Reporting & UI:** Remediation and evidence are generated as Python dataclasses. No output serialisation, CLI, or web interface exists yet.
- **No integration tests:** Only unit tests exist. End-to-end pipeline tests (file → `ComplianceResult`) are not implemented.

---

## Detailed Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full pipeline, normalization model, parser behaviour, engine contract, design decisions |
| [`docs/CONTROLS.md`](docs/CONTROLS.md) | SSH-001, TLN-001, EXEC-001, PWD-001 — per-vendor behaviour, status tables, evidence sanitization |
| [`docs/TESTING.md`](docs/TESTING.md) | Testing strategy, 229-test breakdown, edge cases, coverage gaps |
| [`docs/CONTROL_ROADMAP.md`](docs/CONTROL_ROADMAP.md) | Future control candidates and scoring |
| [`docs/aaa-001-design.md`](docs/aaa-001-design.md) | AAA-001 design (not yet implemented) |
