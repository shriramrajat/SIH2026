# 26164 — ECDAT Backend: Architecture & API Reference

## Overview

26164 is the cryptographic-asset discovery and post-quantum risk assessment backend.
It scans source repositories written in **Python, Java, C/C++, and PEM** and returns
structured findings that map each detected primitive to a NIST PQC migration recommendation.

---

## Module Layout

```
26164/
├── src/
│   ├── api/
│   │   └── main.py          # FastAPI application (transport layer only)
│   └── ecdat/
│       ├── models.py        # CryptoAsset, Evidence  (Pydantic)
│       ├── rules.py         # Regex rule definitions + secret-candidate heuristics
│       ├── ast_parser.py    # Python AST visitor (hardcoded-secret detection)
│       ├── scanner.py       # Scanner class — discovery + regex + AST
│       ├── risk.py          # Deterministic risk classifier + PQC recommendations
│       └── service.py       # ScanService (business logic), Pydantic response models
└── tests/
    ├── fixtures/            # Language-specific fixture files
    ├── test_scanner.py
    ├── test_risk_classification.py
    ├── test_integration.py
    └── test_api.py
```

---

## API Contract

### `GET /health`
Liveness probe.
```json
{ "status": "ok" }
```

### `GET /version`
```json
{ "version": "0.1.0" }
```

### `POST /api/v1/scan`

**Request**
```json
{
  "target_path": "/absolute/path/to/repo",
  "language_filters": ["python", "java"]   // optional
}
```

Supported `language_filters` values: `python`, `java`, `c`, `cpp`, `pem`.

**Success Response**
```json
{
  "summary": {
    "total_files_discovered": 12,
    "total_files_scanned": 5,
    "files_skipped": 0,
    "files_failed": 0,
    "total_crypto_assets": 8,
    "severity_counts":       { "critical": 3, "high": 2, "medium": 2, "low": 1, "info": 0 },
    "quantum_threat_counts": { "shor": 3, "grover": 1, "none": 4 },
    "algorithm_distribution": { "RSA": 2, "AES": 3, "MD5": 2, "SECRET": 1 },
    "quantum_vulnerable_assets": 4
  },
  "findings": [
    {
      "finding_id": "crypto-abc123def456",
      "algorithm": "RSA",
      "category": "asymmetric_encryption",
      "key_length": 2048,
      "mode": null,
      "padding": null,
      "file_location": { "file_path": "src/crypto.py", "line_number": 14 },
      "evidence": {
        "file_path": "src/crypto.py",
        "line_number": 14,
        "code_snippet": "key = RSA.generate(2048)",
        "detection_mechanism": "regex",
        "matched_rule_id": "py-pycryptodome-rsa-generate"
      },
      "risk": {
        "severity": "critical",
        "reason": "RSA is an asymmetric primitive vulnerable to Shor's algorithm.",
        "confidence": 0.95,
        "quantum_threat": "shor",
        "pqc_recommendation": {
          "target_algorithm": "ML-KEM-768",
          "nist_standard": "FIPS 203",
          "migration_type": "Hybrid (ECDH + ML-KEM) or Direct Replacement"
        }
      }
    }
  ],
  "errors": [],
  "skipped_files": [],
  "metadata": {
    "scan_duration_ms": 142,
    "scanner_version": "0.1.0"
  }
}
```

**Error Responses** (HTTP 200, with `error` key)

| `error.code`       | Cause                                      |
|--------------------|--------------------------------------------|
| `INVALID_INPUT`    | `target_path` does not exist               |
| `SCANNER_FAILURE`  | Unrecoverable failure in the Scanner layer |
| `ANALYSIS_FAILURE` | Unrecoverable failure in the Risk layer    |
| `INTERNAL_ERROR`   | Any other unexpected exception             |

---

## Detection Mechanisms

| Mechanism       | Description                                                       |
|-----------------|-------------------------------------------------------------------|
| `regex`         | Pattern match against the rule library in `rules.py`             |
| `ast`           | Python AST visitor detecting hardcoded string/bytes literals      |
| `pem_header`    | PEM `-----BEGIN …-----` header detection                          |

---

## Risk Severity Mapping

| Algorithm family        | Default severity | Quantum threat |
|-------------------------|-----------------|----------------|
| RSA / ECC / DSA / ECDH  | **critical**    | Shor           |
| MD5 / SHA-1 / DES / RC4 | **high**        | —              |
| AES-128 / AES-192       | **medium**      | Grover         |
| AES-256-GCM             | **low**         | —              |
| SHA-256 / SHA-512       | **info**        | —              |
| Hardcoded secret        | **critical**    | —              |
| Unknown algorithm       | **medium**      | —              |

---

## Hardening Notes

- **File failure isolation**: a crash in one file does not abort the scan; the error is
  recorded in `errors[]` and the scan continues.
- **Classification failure isolation**: a crash classifying one asset falls back to MEDIUM
  risk rather than aborting the whole analysis.
- **Resource safety**: files larger than 10 MB are skipped (recorded in `skipped_files[]`).
- **Symlink safety**: symlinks that resolve outside the scan root are skipped.
- **Secret redaction**: code snippets containing hardcoded secrets are redacted before
  being stored or returned in the API response.
- **Path normalisation**: all `file_path` values in the response are relative to the scan
  root and use forward slashes, regardless of host OS.
