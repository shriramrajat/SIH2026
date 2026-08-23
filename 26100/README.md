# PS 26100 — AI-Powered Bid Compliance Verification Core

Project workspace for the PS 26100 bid compliance verification platform for GeM procurement.

The overarching system pipeline is:
```text
Tender document → Requirement extraction → Bidder documents → Evidence extraction 
                → Requirement/evidence matching → Compliance decision → Evidence-backed report
```

### Core Architectural Principle
> **The LLM is not the source of truth.**
>
> Natural language extraction and candidate matching may propose structured facts, but all final compliance evaluations are performed deterministically against evidence. Every compliance result retains direct provenance references to source documents and page numbers.

---

## 1. Current Implementation Status

This repository contains the **Deterministic Compliance Core (Day 2 Milestone)**.

Implemented components:
- **Core Pydantic Domain Models**: Strongly typed schemas for `Requirement`, `Evidence`, and `ComplianceResult`.
- **Deterministic Compliance Engine**: Modular evaluation handlers for numeric constraints (with unit normalization), categorical matching, document presence, and missing/ambiguous evidence.
- **Evidence Provenance Tracking**: Guaranteed retention of `evidence_ids` and page-level source references with hallucination-free explanations.
- **Synthetic Benchmark Fixtures**: 12 synthetic procurement requirements and matching bidder submissions covering all decision paths.
- **Automated Pytest Suite**: 44 unit tests validating all operators, edge cases, unit conversions, and batch bid evaluations.

---

## 2. Core Schemas

All domain models are defined using Pydantic v2 under `src/`:

### `Requirement` (`src/requirements/models.py`)
Represents a structured tender clause or qualification requirement:
- `requirement_id` (`str`): Unique identifier (e.g., `"REQ-001"`).
- `category` (`RequirementCategory`): Classification (`technical_specification`, `mandatory_document`, `eligibility`, `financial`, `experience`, `quantity`, `other`).
- `original_text` (`str`): Verbatim requirement clause extracted from the tender.
- `parameter` (`Optional[str]`): Normalized parameter name (e.g., `"ram"`, `"turnover"`).
- `operator` (`Optional[Operator]`): Evaluation operator (`>=`, `<=`, `>`, `<`, `==`, `!=`, `CONTAINS`, `DOCUMENT_REQUIRED`).
- `required_value` (`Optional[Any]`): Target value or threshold.
- `unit` (`Optional[str]`): Measurement unit (e.g., `"GB"`, `"hours"`, `"Lakhs"`, `"years"`).
- `mandatory` (`bool`): Whether failure to comply disqualifies the bid (default `True`).
- `source_document` / `page`: Provenance location in source tender.
- `extraction_confidence` (`Optional[float]`): Confidence score (0.0–1.0).

### `Evidence` (`src/evidence/models.py`)
Represents a piece of evidence extracted from a bidder's submission:
- `evidence_id` (`str`): Unique identifier (e.g., `"EVID-001"`).
- `requirement_id` (`Optional[str]`): Target requirement ID.
- `document_id` (`Optional[str]`): Bidder filename or document identifier.
- `page` / `section`: Location where evidence appears in the bidder submission.
- `text` (`str`): Verbatim excerpt from the bidder document.
- `extracted_value` (`Optional[Any]`): Structured/normalized value.
- `unit` (`Optional[str]`): Extracted measurement unit.
- `confidence` (`Optional[float]`): Extraction confidence score.
- `is_contradictory` (`bool`): Explicit flag indicating contradictory/revoked evidence.
- `is_partial` (`bool`): Flag indicating partial fulfillment.
- `is_ambiguous` (`bool`): Flag indicating unverified or ambiguous evidence.

### `ComplianceResult` (`src/compliance/models.py`)
Represents an evidence-backed evaluation outcome:
- `requirement_id` (`str`): Target requirement ID.
- `bidder_id` (`Optional[str]`): Bidder identifier.
- `status` (`ComplianceStatus`): Final determination (`COMPLIANT`, `NON_COMPLIANT`, `PARTIALLY_COMPLIANT`, `NEEDS_REVIEW`).
- `comparison` (`Optional[str]`): Deterministic comparison string (e.g., `"32 GB >= 16 GB"`).
- `explanation` (`str`): Factual, evidence-backed justification citing document ID and page.
- `confidence` (`Optional[float]`): Confidence of evaluation (1.0 for deterministic evaluation).
- `evidence_ids` (`list[str]`): IDs of all evidence items used.

---

## 3. Allowed Compliance States

The engine strictly maps decisions to four standardized states:

| State | Definition | Example Scenario |
|---|---|---|
| `COMPLIANT` | Evidence deterministically meets or exceeds the requirement. | Required RAM $\ge 16\text{ GB}$; bidder provides $32\text{ GB}$. |
| `NON_COMPLIANT` | Evidence deterministically fails or contradicts the requirement. | Required RAM $\ge 16\text{ GB}$; bidder provides $8\text{ GB}$. |
| `PARTIALLY_COMPLIANT` | Evidence meets a subset of requirements but is incomplete. | 3 client reference letters required; bidder submits 1 letter. |
| `NEEDS_REVIEW` | Missing evidence, ambiguous values, incompatible units, or unparseable data. | No experience document submitted, or unverified draft financial figures. |

> [!IMPORTANT]
> The engine **never assumes compliance** when evidence is missing, and **never invents missing values**. Missing or ambiguous inputs always produce `NEEDS_REVIEW`.

---

## 4. Supported Operators & Unit Normalization

### Operators
- **Numeric**: `>=`, `<=`, `>`, `<`, `=`, `==`, `!=`
- **Categorical / Text**: `==`, `=`, `EXACT`, `CONTAINS`, `!=`
- **Document / Presence**: `DOCUMENT_REQUIRED`, `EXISTS`, `PRESENT`

### Unit Conversion (`src/compliance/units.py`)
The engine includes lightweight normalization for standard procurement units:
- **Digital Storage**: `B`, `KB`, `MB`, `GB`, `TB` (e.g., $2048\text{ GB} \ge 1\text{ TB} \rightarrow \text{COMPLIANT}$).
- **Time**: `hours`, `days`, `weeks`, `months`, `years` (e.g., $12\text{ hours} \le 1\text{ day} \rightarrow \text{COMPLIANT}$).
- **Financial Multiples**: `INR`, `Rs`, `Lakhs`, `Crores` (e.g., $150\text{ Lakhs} \ge 1\text{ Crore} \rightarrow \text{COMPLIANT}$).
- **Percentages**: `%`, `percent`.

If units are incompatible or ambiguous (e.g., comparing `GB` with `kg`), the engine conservatively returns `NEEDS_REVIEW`.

---

## 5. Running Tests

To run the automated test suite from the repository root:

```powershell
python -m pytest 26100/tests/ -v
```

All 44 test cases cover:
- Schema validation, defaults, and serialization (`test_schemas.py`)
- Numeric operators, boundary checks, and unit conversion (`test_numeric_comparisons.py`)
- Categorical equality, case-insensitivity, and string matching (`test_categorical_comparisons.py`)
- Document presence and revocation checks (`test_document_presence.py`)
- Missing, empty, and ambiguous evidence handling (`test_missing_and_ambiguous_evidence.py`)
- Evidence provenance tracking and factual explanations (`test_provenance_and_explanations.py`)
- Batch evaluation over the synthetic benchmark dataset (`test_engine_batch.py`)

---

## 6. Directory Structure

```text
26100/
├── README.md
├── docs/
│   └── day-1-technical-design.md
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── compliance/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── models.py
│   │   ├── units.py
│   │   └── evaluators/
│   │       ├── __init__.py
│   │       ├── categorical.py
│   │       ├── numeric.py
│   │       └── presence.py
│   ├── evidence/
│   │   ├── __init__.py
│   │   └── models.py
│   └── requirements/
│       ├── __init__.py
│       └── models.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── fixtures/
    │   ├── __init__.py
    │   └── synthetic_tender_bid.py
    └── unit/
        ├── __init__.py
        ├── test_categorical_comparisons.py
        ├── test_document_presence.py
        ├── test_engine_batch.py
        ├── test_missing_and_ambiguous_evidence.py
        ├── test_numeric_comparisons.py
        ├── test_provenance_and_explanations.py
        └── test_schemas.py
```

---

## 7. Current Limitations & Next Steps

### Current Limitations (By Design for this Phase)
- **No PDF Ingestion / OCR**: The current engine evaluates structured Pydantic objects. Ingestion from PDF files and scanned OCR is scheduled for subsequent phases.
- **No LLM Extraction**: Requirement and evidence extraction from raw text via NLP/LLMs is not yet active.
- **No Web API / Frontend**: FastAPI routes and web dashboards are not included in this core engine milestone.
- **No Production GeM Integration**: Direct connection to live GeM portals is out of scope for this stage.

### Recommended Next Step
Implement the **Document Ingestion & Text Extraction layer** (`26100/src/ingestion/` and `26100/src/extraction/`) to convert tender and bidder PDFs into candidate text chunks with page tracking.
