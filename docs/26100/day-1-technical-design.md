# PS 26100 — Day 1 Technical Design

## 1. Problem Understanding

PS 26100 is an AI-powered bid compliance verification problem for GeM procurement. The POC should determine whether bidder-submitted evidence satisfies structured tender requirements.

Core workflow:

Tender document → requirement extraction → bidder documents → evidence extraction → requirement/evidence matching → compliance decision → evidence-backed report.

Primary users are procurement/tender evaluation teams who currently need to inspect tender clauses and bidder submissions manually and consistently determine compliance.

### Inputs

- Tender documents (initially PDF)
- Bidder documents (initially PDF)
- Supporting certificates/specifications where available

### Outputs

For each requirement:

- requirement ID and text
- category/parameter/operator/value where extractable
- bidder evidence
- source document and page/section
- comparison/explanation
- status: COMPLIANT, NON_COMPLIANT, PARTIALLY_COMPLIANT, or NEEDS_REVIEW
- confidence

## 2. Real-World Challenges

- Requirements may be buried in long tender documents.
- Requirements can be explicit numeric constraints, categorical conditions, document requirements, or ambiguous natural language.
- Bidder evidence may be spread across multiple pages/documents.
- PDFs may contain tables or scanned images requiring OCR.
- Extracted values can have units, ranges, synonyms, or formatting differences.
- Missing evidence is different from evidence of failure.
- LLM output can hallucinate facts and therefore must not be treated as authoritative evidence.

## 3. Existing-Solution Landscape

Relevant solution categories include:

1. Procurement/tender-management platforms — strong workflow and document management, but often broader than evidence-backed automated compliance verification.
2. Generic document-intelligence/OCR platforms — strong extraction, but extraction alone does not prove procurement compliance.
3. RAG/PDF-chat systems — useful for retrieval and question answering, but a generic chatbot does not provide structured requirement/evidence comparison.
4. Rule-based compliance systems — explainable for explicit constraints, but weak for extracting requirements and matching semantically equivalent evidence.

The POC differentiation should therefore be the combination of structured requirement extraction, evidence provenance, deterministic comparisons for explicit requirements, and AI assistance only for ambiguous extraction/matching.

## 4. Gap Analysis / Differentiation

The POC should not compete by claiming generic “AI document analysis.” The stronger technical claim is:

**Tender requirement → structured requirement → evidence with provenance → deterministic/semantic comparison → explainable compliance result.**

Every result should be traceable to source text/page evidence.

## 5. POC Scope

### MUST HAVE

- PDF ingestion
- Text extraction
- Page-aware source references
- Initial OCR path for scanned pages
- Requirement extraction for a controlled set of requirement categories
- Structured requirement schema
- Bidder evidence extraction
- Requirement/evidence matching
- Deterministic comparison for explicit numeric/categorical requirements
- Four-state result: compliant, non-compliant, partially compliant, needs review
- Evidence-backed result explanation
- Basic API
- Small reproducible test dataset

### NICE TO HAVE

- Table extraction
- Multiple bidder comparison
- Confidence calibration
- Human review/edit of extracted requirements
- Report export
- Semantic retrieval using embeddings

### NOT NEEDED NOW

- Full GeM production integration
- Enterprise authentication/authorization
- Complex workflow management
- Large-scale distributed processing
- Fine-tuning a custom LLM
- Autonomous procurement decisions
- Full dashboard polish before the core engine works

## 6. Requirement Extraction Strategy

Use a hybrid pipeline:

PDF → text/page extraction → candidate clause segmentation → LLM structured extraction → schema validation → normalization → human-review-ready requirement records.

Initial categories:

- eligibility
- technical specification
- mandatory document/certificate
- financial requirement
- experience requirement
- quantity/specification
- deadline/condition

Example normalized record:

```json
{
  "requirement_id": "REQ-001",
  "category": "hardware",
  "parameter": "ram",
  "operator": ">=",
  "required_value": 16,
  "unit": "GB",
  "source_document": "tender.pdf",
  "page": 12
}
```

Do not force every natural-language clause into a numeric rule. Clauses that cannot be safely structured should remain textual/semantic requirements and may be classified as NEEDS_REVIEW when evidence is ambiguous.

## 7. Evidence Extraction Strategy

Bidder PDF → page-aware extraction/OCR → candidate evidence chunks → retrieval against requirement → structured evidence extraction → provenance record.

Evidence record should contain:

- document ID
- page/section
- extracted text/value
- evidence type
- requirement ID when matched
- confidence

Missing evidence must produce no invented value. It should produce NEEDS_REVIEW or a missing-evidence state mapped to the project's four-state output model.

## 8. Compliance Engine

Use deterministic logic whenever the requirement and evidence are structured.

Example:

Required RAM >= 16 GB
Bidder RAM = 8 GB

8 >= 16 → false → NON_COMPLIANT.

For categorical/document requirements:

- matching certificate found → COMPLIANT
- explicit contradictory evidence → NON_COMPLIANT
- incomplete/ambiguous evidence → PARTIALLY_COMPLIANT or NEEDS_REVIEW
- no relevant evidence → NEEDS_REVIEW

Semantic/LLM matching may propose a relationship, but the engine should retain the source evidence and avoid presenting unsupported claims as facts.

## 9. Data Model

Core entities:

### Tender
- id
- title
- source documents
- metadata

### Requirement
- id
- tender_id
- category
- original_text
- parameter
- operator
- required_value
- unit
- mandatory
- source_document
- page
- extraction_confidence

### Bidder
- id
- name
- tender_id

### Document
- id
- bidder_id/tender_id
- filename
- document_type
- hash
- page_count

### Evidence
- id
- requirement_id
- document_id
- page
- section
- text
- extracted_value
- unit
- confidence

### ComplianceResult
- id
- requirement_id
- bidder_id
- status
- comparison
- explanation
- confidence
- evidence_ids

## 10. Architecture

```text
React + TypeScript UI
          |
       FastAPI
          |
  Document Ingestion
          |
   PDF/OCR Extraction
          |
   -----------------
   |               |
Requirement      Evidence
Extraction       Extraction
   |               |
   ------ Matching ------
             |
     Compliance Engine
             |
        PostgreSQL
             |
     Report / API output
```

The initial implementation can keep these as Python modules rather than microservices.

Recommended backend modules:

- ingestion
- extraction
- requirements
- evidence
- matching
- compliance
- reports
- API routes

## 11. AI Strategy

### Rule-based
Best for:

- numeric comparison
- dates
- quantities
- ranges
- exact/categorical conditions
- required-document presence checks

### LLM/NLP
Useful for:

- requirement classification
- converting natural language into candidate structured requirements
- semantic evidence matching
- resolving synonyms and varied phrasing

### Hybrid decision

LLM/NLP proposes structured information → schema validation/normalization → deterministic engine verifies explicit constraints → evidence provenance is retained → ambiguous cases go to NEEDS_REVIEW.

Do not allow an LLM to invent evidence, silently infer missing values, or make an unsupported final compliance decision.

## 12. Technology Stack

### Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- PostgreSQL
- Pytest
- Ruff

### Document processing

- PyMuPDF for PDF text/page extraction
- OCR engine only when pages are image/scanned content
- Table extraction evaluated separately after baseline text extraction works

### AI

- LLM API for structured extraction and ambiguous semantic matching
- JSON-schema/Pydantic validation around model outputs
- Embeddings/vector search only if baseline retrieval proves insufficient

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui

### Engineering

- Git/GitHub feature branches + PRs
- Docker later for reproducibility

## 13. Strong Demo Flow

Use a small synthetic but realistic tender/bid pair with explicit requirements.

Example:

Tender:
- Minimum RAM: 16 GB
- ISO 9001 certification required
- Minimum 3 years relevant experience

Bidder documents:
- Product specification showing 8 GB RAM
- ISO 9001 certificate
- Experience document showing 5 years

Expected output:

- RAM → NON_COMPLIANT, with page-backed 8 GB evidence
- ISO 9001 → COMPLIANT, with certificate/page evidence
- Experience → COMPLIANT, with 5-year evidence

A second test case should omit one required document to demonstrate NEEDS_REVIEW rather than hallucinated compliance.

## 14. Risks and Mitigations

### Hallucination
Mitigation: evidence-required outputs, schema validation, deterministic comparison, no invented values.

### OCR errors
Mitigation: preserve OCR confidence/page source, flag low-confidence extraction, allow review.

### Missing evidence
Mitigation: explicit missing/needs-review state; never assume compliance.

### False positives
Mitigation: conservative semantic matching thresholds and evidence display.

### False negatives
Mitigation: synonym-aware retrieval and multiple candidate evidence chunks.

### Document manipulation
Mitigation: retain original file hash and source metadata; treat uploaded documents as untrusted evidence.

### Privacy/security
Mitigation: avoid storing unnecessary personal data, protect uploads, keep secrets out of source control, define retention policy.

### Ambiguous requirements
Mitigation: preserve original clause and route ambiguous cases to human review.

## 15. Implementation Roadmap

### POC v0

- repository structure
- PDF text extraction
- page-aware chunks
- hand-authored sample requirements
- hand-authored evidence
- deterministic compliance engine
- tests

Success criterion: compliance logic is correct and reproducible.

### POC v1

- automated requirement extraction
- automated evidence extraction
- structured schemas
- evidence retrieval
- confidence/provenance

Success criterion: end-to-end tender → bid → compliance works on a controlled dataset.

### Stronger Prototype

- OCR
- tables
- semantic matching
- human review workflow
- report generation
- multiple bidders

Success criterion: robust demo across varied document formats and requirement types.

### SIH Demo

- polished UI
- representative tender/bid dataset
- explainable compliance matrix
- performance/accuracy measurements
- security/privacy controls
- architecture and differentiation story

## 16. Open Questions

1. Which actual GeM tender document(s) will be used as the evaluation dataset?
2. Which languages and document formats must the POC support?
3. Which OCR engine/API is acceptable under the team's cost/privacy constraints?
4. Which LLM provider/model is approved by Rajat?
5. What accuracy threshold is required before semantic matching is trusted?
6. Which requirement categories should be the first benchmark?
7. How will human review decisions be recorded for future evaluation?

## 17. Recommended Day 2 Starting Point

Do not start with the frontend or an LLM chatbot.

Start with the compliance core:

1. Define Pydantic schemas for Requirement, Evidence, and ComplianceResult.
2. Implement deterministic operators (`>=`, `<=`, `=`, presence/categorical match).
3. Create a tiny synthetic tender/bid fixture with 8–10 requirements covering pass, fail, partial, and missing evidence.
4. Write Pytest cases for every decision type.
5. Add page/source provenance to the fixture model.
6. Only after the engine passes tests, implement PDF ingestion.

This creates a reliable foundation for later AI extraction rather than allowing the LLM to become the system's source of truth.
