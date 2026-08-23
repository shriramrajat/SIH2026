# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
## Day 1: CBOM & Data Structure Specification (PS 26164)

---

### 1. Internal Asset Data Model

Before exporting to CycloneDX 1.6, ECDAT normalizes all discovered cryptographic occurrences into a uniform internal JSON structure:

```json
{
  "asset_id": "crypto-asset-001",
  "name": "RSA Private Key Generation",
  "category": "asymmetric_encryption",
  "algorithm": "RSA",
  "key_length": 2048,
  "mode": null,
  "padding": "OAEP",
  "file_path": "src/auth/crypto_service.py",
  "line_number": 42,
  "code_snippet": "key = RSA.generate(2048)",
  "library": "PyCryptodome",
  "confidence": 0.95,
  "quantum_risk": {
    "status": "VULNERABLE",
    "severity": "CRITICAL",
    "quantum_threat": "Broken by Shor's Algorithm",
    "grace_period_years": 0
  },
  "pqc_recommendation": {
    "target_algorithm": "ML-KEM-768 (Kyber)",
    "nist_standard": "FIPS 203",
    "migration_type": "Hybrid Classical/PQC or Direct Replacement"
  }
}
```

---

### 2. CycloneDX 1.6 CBOM Mapping Format

ECDAT formats the final output to comply with the official **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** standard:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-08-23T20:00:00Z",
    "tools": [
      {
        "vendor": "SIH-2026-Team",
        "name": "ECDAT",
        "version": "0.1.0-poc"
      }
    ]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA",
      "bom-ref": "crypto-asset-001",
      "evidence": {
        "occurrences": [
          {
            "location": "src/auth/crypto_service.py",
            "line": 42,
            "offset": 0
          }
        ]
      },
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "public-key-encryption",
          "parameterSetIdentifier": "2048",
          "executionEnvironment": "software-user-space",
          "cryptoFunctions": ["keygen", "encrypt", "decrypt"]
        },
        "oid": "1.2.840.113549.1.1.1"
      }
    }
  ]
}
```
