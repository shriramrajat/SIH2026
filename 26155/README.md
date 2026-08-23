# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

## Problem Statement

| Field        | Value                                              |
|--------------|----------------------------------------------------|
| **PS ID**    | SIH 26155                                          |
| **Org**      | National Technical Research Organisation (NTRO)    |
| **Category** | Software                                           |
| **Theme**    | Blockchain & Cybersecurity                         |

---

## Current Purpose

This is the **foundation layer** (Layer 1) of the compliance auditor.

The foundation makes it possible to:

1. Load a network device configuration file from disk.
2. Detect which vendor the configuration belongs to.
3. Parse a Cisco IOS / IOS-XE configuration into a structured representation.
4. Convert that structured representation into a vendor-neutral model.

No compliance analysis, AI, remediation, or reporting exists yet — those
layers depend on this foundation being correct and stable first.

---

## Current Architecture

```
Configuration file
       │
       ▼
┌──────────────────────┐
│  Ingestion           │   src/ingestion/
│  ├── loader.py       │   Read the raw file from disk
│  └── detector.py     │   Identify the vendor
└──────────┬───────────┘
           │  raw text + vendor tag
           ▼
┌──────────────────────┐
│  Parser              │   src/parsers/
│  └── cisco.py        │   Cisco IOS / IOS-XE foundation parser
└──────────┬───────────┘
           │  vendor-specific parsed data
           ▼
┌──────────────────────┐
│  Normalization       │   src/normalization/
│  └── model.py        │   Vendor-neutral configuration model
└──────────────────────┘
           │
           ▼
    NormalizedConfig
    (ready for a future compliance engine)
```

### Module map

| Module | Responsibility |
|--------|---------------|
| `src/ingestion/loader.py` | Accept a file path, validate it, return UTF-8 text |
| `src/ingestion/detector.py` | Inspect raw text, return `"cisco"` or `"unknown"` |
| `src/parsers/cisco.py` | Parse Cisco IOS text → structured sections + items |
| `src/normalization/model.py` | Dataclass hierarchy: `NormalizedConfig`, `ConfigSection`, `ConfigItem` |

---

## How Ingestion Works

### Loading (`loader.py`)

```python
from src.ingestion.loader import load_config

raw = load_config("path/to/router.conf")
```

`load_config` will:
- Raise `FileNotFoundError` if the path does not exist.
- Raise `ValueError` if the path is a directory rather than a file.
- Return the file content as a UTF-8 string.

### Detection (`detector.py`)

```python
from src.ingestion.detector import detect_vendor

vendor = detect_vendor(raw)   # "cisco" | "unknown"
```

Detection is based on recognising patterns that are unambiguously Cisco:
`version <n>`, `hostname`, `enable secret`, `ip ssh version`.  Detection
is intentionally conservative — if uncertain it returns `"unknown"` rather
than guessing.

### Parsing + Normalization

```python
from src.parsers.cisco import parse_cisco

config = parse_cisco(raw)           # NormalizedConfig
print(config.hostname)              # "LAB-ROUTER-01"
print(config.vendor)                # "cisco"

section = config.get_section("line vty 0 4")
item    = config.get_global("version")
```

---

## Currently Supported Vendor

| Vendor | Status |
|--------|--------|
| **Cisco IOS / IOS-XE** | ✅ Foundation parser implemented |
| Juniper | ❌ Not yet |
| Others | ❌ Not yet |

---

## Current Limitations

- **Cisco only.** No other vendors are supported.
- **Structural parsing only.** The Cisco parser extracts hostname, top-level
  directives, and block sections.  It does not attempt to fully parse every
  IOS command.
- **No compliance engine.** `NormalizedConfig` is a data container; it
  contains no compliance rules.
- **No AI, remediation, or reporting.** Those layers are out of scope for
  this foundation.
- **Detection is heuristic.** Unusual or heavily stripped Cisco configs may
  yield `"unknown"`.

---

## How to Run Tests

### Prerequisites

- Python 3.11 or later (tested on 3.13)
- `pytest` installed (`pip install pytest`)

### Run all unit tests

From the **repository root** (`SIH2026/`):

```bash
python -m pytest 26155/tests/unit/ -v
```

The `conftest.py` in `26155/` automatically adds the `26155/` directory to
`sys.path` so that `src` is importable without installing a package.

### Expected output

```
45 passed in ~0.4s
```

### Fixture

`tests/fixtures/cisco-basic.conf` contains a harmless sample Cisco
configuration used by several tests.  It contains no real credentials,
secrets, IP addresses, or production data.

---

## Current Status

Foundation layer complete.  
Next step: implement a Juniper parser so that both vendors can produce the
same `NormalizedConfig`, proving the normalization model is vendor-neutral.