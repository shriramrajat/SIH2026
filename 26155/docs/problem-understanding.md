# PS 26155 — Problem Understanding

## 1. Problem Statement

**AI-Driven Multi-Vendor Network Security Compliance Auditor**

The goal is to build a Proof of Concept (POC) that can analyze network-device configurations from different vendors and determine whether they comply with defined security requirements.

The system should convert vendor-specific configurations into a common, vendor-neutral representation and then evaluate that representation against defined security compliance rules.

The POC should focus on producing **explainable, evidence-backed compliance results** rather than simply generating an AI-based score.

---

## 2. Core Problem

Network environments commonly contain devices from multiple vendors.

Different vendors use different:

- Configuration syntax
- Command structures
- Security terminology
- Feature representations
- Configuration hierarchies

This makes manual security auditing difficult and inconsistent.

Our system should solve this by creating the following pipeline:

```text
Vendor Configuration
        ↓
Configuration Parser
        ↓
Vendor-Specific Model
        ↓
Vendor-Neutral Normalization
        ↓
Security Compliance Engine
        ↓
Compliance Result
        ↓
Report / Remediation
```

---

## 3. Primary Inputs

The initial POC will accept network-device configuration files.

Initial supported format:

- Plain-text configuration files

Initial vendor support:

- Cisco
- One additional vendor selected during implementation

The architecture must allow additional vendors to be added without rewriting the compliance engine.

---

## 4. Expected Outputs

For every evaluated security control, the system should provide:

- Control ID
- Control name
- Compliance status
- Evidence from the configuration
- Relevant configuration section/line
- Explanation
- Severity
- Remediation recommendation where applicable

Example:

```text
Control: SSH Version
Status: NON_COMPLIANT
Severity: HIGH

Evidence:
ip ssh version 1

Expected:
SSH version 2

Remediation:
Configure the device to use SSH version 2.
```

---

## 5. Vendor-Neutral Normalization

The most important architectural component is the vendor-neutral representation.

The compliance engine should not directly depend on Cisco, Juniper, or another vendor's syntax.

Instead:

```text
Cisco Config ──────┐
                   │
                   ↓
             Normalized Model
                   ↑
                   │
Juniper Config ────┘
                   │
                   ↓
          Compliance Engine
```

For example, different vendor-specific configurations representing the same security concept should produce the same normalized security state.

Conceptually:

```json
{
  "control": "secure_management_protocol",
  "state": "enabled",
  "protocol": "ssh",
  "version": 2
}
```

This allows the compliance rules to remain vendor-neutral.

---

## 6. Initial Compliance Scope

The first POC should focus on a small but meaningful set of network security controls.

Initial candidates include:

- Secure management protocols
- SSH configuration
- Telnet usage
- Password/security policy
- Privileged access
- Unused services
- Access control configuration
- Logging configuration
- Network management security

The exact controls will be finalized after configuration samples from the selected vendors are analyzed.

---

## 7. Compliance Result Model

The system should avoid a simple binary compliant/non-compliant model.

Initial result states:

```text
COMPLIANT
NON_COMPLIANT
PARTIALLY_COMPLIANT
NOT_APPLICABLE
NEEDS_REVIEW
```

Every result should contain supporting evidence.

The system must not claim compliance when the required configuration evidence cannot be established.

---

## 8. AI Role

AI should assist the system rather than become the source of truth.

AI may be used for:

- Configuration interpretation
- Semantic normalization
- Mapping vendor-specific concepts
- Identifying potentially relevant configuration sections
- Generating remediation explanations

Deterministic rules should remain responsible for:

- Explicit configuration checks
- Security-control evaluation
- Compliance decisions where the required state is clearly defined

The system must not rely on an LLM alone to determine whether a security control is satisfied.

---

## 9. Evidence and Explainability

Every compliance decision should be traceable to the original configuration.

The system should preserve:

```text
Configuration
    ↓
Relevant configuration line/section
    ↓
Normalized representation
    ↓
Compliance rule
    ↓
Result
```

A user should be able to understand **why** a device was marked compliant or non-compliant.

---

## 10. Remediation

For non-compliant controls, the system should provide a remediation recommendation.

Remediation should be:

- Specific
- Vendor-aware
- Based on the detected configuration
- Separated from the compliance decision

The system should never silently modify the original configuration.

---

## 11. POC Scope

### MUST HAVE

- Configuration file ingestion
- Support for at least two vendors
- Vendor-specific parsing
- Vendor-neutral normalization
- Security compliance rules
- Evidence-backed results
- Compliance status
- Basic remediation recommendations
- Test configurations
- Reproducible results

### NICE TO HAVE

- AI-assisted normalization
- Additional vendors
- Configuration diffing
- Compliance reports
- Multiple compliance frameworks
- Web interface
- Automated remediation generation

### NOT NEEDED NOW

- Production-scale infrastructure
- Large enterprise dashboard
- Support for every network vendor
- Autonomous configuration changes
- Fine-tuning a custom LLM
- Full enterprise authentication
- Large-scale distributed processing

---

## 12. Key Technical Challenges

### Vendor Differences

Equivalent security configurations may use completely different syntax across vendors.

### Configuration Complexity

Network configurations can contain nested sections, dependencies, defaults, and context-sensitive commands.

### Normalization

The system must preserve security meaning while removing unnecessary vendor-specific syntax.

### Compliance Accuracy

Incorrect normalization can produce false compliance results.

### Explainability

Every result must have traceable evidence.

### AI Reliability

AI-generated interpretations must be validated before they influence compliance decisions.

---

## 13. Initial Architecture Direction

The initial POC should use a modular architecture:

```text
Configuration File
       ↓
   Ingestion
       ↓
Vendor Detection
       ↓
Vendor Parser
       ↓
Normalized Configuration
       ↓
Compliance Engine
       ↓
Evidence + Result
       ↓
Remediation
       ↓
Report / API
```

Suggested modules:

```text
ingestion/
parsers/
normalization/
compliance/
evidence/
remediation/
reports/
```

The initial implementation should remain a modular application rather than being split into microservices.

---

## 14. Engineering Principles

We prioritize:

- Correctness
- Security
- Explainability
- Vendor neutrality
- Reproducibility
- Testability
- Modular architecture
- Evidence-backed decisions

We avoid:

- Blind LLM decisions
- Hardcoded vendor logic inside compliance rules
- Unsupported compliance claims
- Premature microservices
- Unnecessary dependencies
- Autonomous configuration modification
- Scope creep

---

## 15. Day 1 Success Criteria

Day 1 is successful when the team has a clear answer to:

1. What problem are we solving?
2. What configurations do we accept?
3. Which vendors will the initial POC support?
4. What does vendor-neutral normalization mean?
5. Which security controls will we initially evaluate?
6. What evidence must accompany every compliance result?
7. Where does AI help?
8. Where must deterministic logic be used?
9. What is inside the POC?
10. What is explicitly outside the POC?

No production implementation is required at this stage.