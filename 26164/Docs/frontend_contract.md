# ECDAT Frontend/Backend Integration Contract
**Status:** MVP Design
**Module:** 26164 Analysis Layer & Scanner Integration

This document defines the minimal backend API contract required to connect the Python `ecdat` scanner and analysis layers to a frontend dashboard.

---

## 1. Analysis Endpoint

**Operation**: `POST /api/v1/scan`
**Description**: Triggers a cryptographic scan on a target directory and synchronously returns the aggregated results and quantum risk analysis.

### 2. Input Contract

The frontend must provide the target location to scan. For the MVP, this assumes a local file path (or a pre-mounted volume).

```json
{
  "target_path": "/mnt/repos/target-application",
  "language_filters": ["python", "java", "c"] // Optional
}
```

### 3. Output Contract

The backend will orchestrate the scanner (`CryptoAsset` generation) and the analysis layer (`RiskAssessment` generation), and join them by `asset_id` to form a unified `Finding` object.

```json
{
  "summary": {
    "total_files_scanned": 1542,
    "total_crypto_assets": 12,
    "severity_counts": {
      "critical": 2,
      "high": 1,
      "medium": 4,
      "low": 3,
      "info": 2
    },
    "quantum_threat_counts": {
      "shor": 2,
      "grover": 4,
      "none": 6
    },
    "algorithm_distribution": {
      "RSA": 2,
      "AES": 7,
      "SHA-256": 2,
      "MD5": 1
    }
  },
  "findings": [
    // Array of Finding objects (see Section 4)
  ],
  "metadata": {
    "scan_duration_ms": 1450,
    "scanner_version": "0.1.0"
  }
}
```

### 4. Finding Structure (Joined Object)

The frontend requires a flattened/unified view of the asset and its risk. The backend API is responsible for zipping `CryptoAsset` and `RiskAssessment` into a `Finding`.

```json
{
  "finding_id": "crypto-8f9d3a2b", // from CryptoAsset.asset_id
  "algorithm": "RSA",
  "category": "digital_signature",
  "file_location": {
    "file_path": "src/auth/RSASigner.java",
    "line_number": 42
  },
  "evidence": {
    "code_snippet": "Signature.getInstance(\"SHA256withRSA\");",
    "detection_mechanism": "regex",
    "matched_rule_id": "java-signature-instance"
  },
  "risk": {
    "severity": "critical",
    "reason": "RSA is an asymmetric primitive vulnerable to Shor's algorithm.",
    "confidence": 0.80,
    "quantum_threat": "shor",
    "pqc_recommendation": {
      "target_algorithm": "ML-DSA-65",
      "nist_standard": "FIPS 204",
      "migration_type": "Direct Replacement"
    }
  }
}
```

### 5. Dashboard Requirements (MVP)

The frontend dashboard landing page must display:
- **High-level Stats**: Total files scanned, total assets found.
- **Risk Posture**: A doughnut chart or metric cards for `critical`, `high`, `medium`, `low`, `info` counts.
- **Quantum Exposure**: A distinct callout for `quantum_vulnerable_assets` (sum of `shor` + `grover`).
- **Algorithm Inventory**: A bar chart or table showing the `algorithm_distribution` map.
- **Findings Data Grid**: A paginated/sortable list of all findings. Columns: Severity, Algorithm, File Path, Line, PQC Target.

### 6. Finding Detail Requirements (MVP)

When a user clicks on a row in the Findings Data Grid, a detail pane/modal must display:
- **Exact Location**: Clickable file path and line number.
- **Source Context**: The `evidence.code_snippet` displayed in a mono-spaced code block.
- **Risk Explanation**: The full `risk.reason` string.
- **Migration Path**: The `pqc_recommendation` fields (`target_algorithm` and `nist_standard`) styled as actionable remediation advice.
- **Detection Confidence**: The `confidence` score.

### 7. Stable IDs

`asset_id` (mapped to `finding_id`) is currently generated using `uuid.uuid4().hex[:8]`. 
- **Frontend Implication**: The ID is unique per scan but NOT deterministic across multiple scans of the same codebase. 
- **Resolution**: For MVP, the frontend should treat `finding_id` as ephemeral (valid only for the current scan session). If tracking findings over time is required later, the backend MUST be upgraded to generate deterministic SHA-256 IDs based on `(file_path, line_number, algorithm)`.

### 8. Error States

The backend must return standard HTTP status codes and a consistent error payload:

```json
{
  "error": {
    "code": "SCANNER_FAILURE", // e.g., INVALID_INPUT, UNSUPPORTED_LANGUAGE, ANALYSIS_FAILURE
    "message": "Failed to read target directory permissions."
  }
}
```

- **Empty Repository**: Return `200 OK` with `0` assets and empty `findings` list.
- **Unknown Algorithm**: Handled gracefully by the analysis layer (returns `MEDIUM` severity, `NONE` quantum threat). Never throws a `500`.

### 9. MVP vs Later

**In Scope for MVP:**
- Synchronous `POST /api/v1/scan` returning the full JSON payload.
- Unified `Finding` objects.
- Read-only dashboard visualization.
- Standard error state handling.

**NOT In Scope (Deferred):**
- Asynchronous polling (`/scan/status`) or webhooks.
- Historical trend tracking across multiple scans (requires deterministic IDs).
- Code remediation / automated PR generation.
- CycloneDX 1.6 XML/JSON export (this is a separate backend concern, not required for the interactive UI).
- Real-time IDE integration.
