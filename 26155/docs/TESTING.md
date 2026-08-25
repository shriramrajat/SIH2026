# PS 26155 — Testing Strategy and Coverage

## Summary

- **Test type:** Unit tests only (no integration tests, no end-to-end pipeline tests)
- **Test count:** **229 passing** (verified on main branch, August 2026)
- **Location:** `26155/tests/unit/`
- **Fixtures:** `26155/tests/fixtures/`
- **Runner:** `python -m pytest 26155/tests/unit/ -v` (from repository root)

---

## Test Files

| File | Focus | Tests (approx.) |
|---|---|---|
| `test_ingestion.py` | `load_config()`, `detect_vendor()` | ~10 |
| `test_cisco_parser.py` | `parse_cisco()` — sections, items, hostname, edge cases | ~20 |
| `test_juniper_parser.py` | `parse_juniper()` — blocks, leaf items, comment stripping, depth handling | ~35 |
| `test_normalization.py` | `NormalizedConfig`, `ConfigSection`, `ConfigItem` data model | ~15 |
| `test_compliance_model.py` | `ComplianceResult`, `Evidence`, `Remediation`, enums | ~10 |
| `test_ssh_version_rule.py` | SSH-001 — Cisco, Juniper, evidence, remediation, engine | ~50 |
| `test_telnet_disabled_rule.py` | TLN-001 — Cisco multi-VTY, Juniper, evidence | ~60 |
| `test_exec_timeout_rule.py` | EXEC-001 — Cisco multi-VTY, Juniper, edge cases | ~30 |
| `test_pwd_encryption_rule.py` | PWD-001 — hash classification, secret redaction | ~30 |

> The authoritative count is the pytest output: **229 passed**.

---

## Test Fixtures

| Fixture | Description |
|---|---|
| `tests/fixtures/cisco-basic.conf` | Minimal Cisco IOS config: hostname, SSH v2, `transport input ssh`, `no service telnet`. No real credentials or IPs. |
| `tests/fixtures/juniper-basic.conf` | Minimal JunOS config: system block with SSH v2, interfaces, routing, security zones. No real credentials. |

Inline configs (constructed as Python strings inside each test function) are used extensively for rule tests.

---

## Coverage by Category

### Parser Tests

| Category | Cisco | Juniper |
|---|---|---|
| Hostname extraction | ✅ | ✅ |
| Section / block identification | ✅ | ✅ |
| Global item extraction | ✅ | ✅ |
| Indented sub-command handling | ✅ | — |
| Brace depth tracking | — | ✅ |
| Comment stripping (`!` / `#` / `##`) | ✅ | ✅ |
| Blank line handling | ✅ | ✅ |
| `end` marker handling | ✅ | — |
| Nested block flattening | — | ✅ |
| Malformed / truncated config (graceful) | ✅ | ✅ |
| Raw line preservation | ✅ | ✅ |
| Multiple sections of same type | ✅ | ✅ |

### Compliance Rule Tests (all four rules)

| Category | Description |
|---|---|
| PASS cases | Directive present with compliant value |
| FAIL (bad value) | Directive present with non-compliant value |
| FAIL (absent) | Required directive missing entirely |
| NEEDS_REVIEW | Value is ambiguous, malformed, or unrecognised |
| NOT_APPLICABLE | Unsupported vendor → `NOT_APPLICABLE` |
| Evidence presence | All statuses produce ≥1 `Evidence` record |
| Absence evidence | Missing directive → `raw_lines=()` |
| Raw line in evidence | Present directive → `raw_lines` contains original line |
| Evidence `control_id` | Matches rule's `control.control_id` |
| Remediation on FAIL | FAIL returns vendor-specific remediation |
| No remediation on non-FAIL | PASS / NEEDS_REVIEW / NOT_APPLICABLE → empty remediations |
| Vendor isolation | Cisco FAIL → only Cisco remediation; Juniper FAIL → only Juniper remediation |
| Severity | Result severity matches static control metadata |
| Framework refs | Non-empty framework references in result |
| Hostname propagation | `config.hostname` propagated to `ComplianceResult.hostname` |
| Vendor propagation | `config.vendor` propagated to `ComplianceResult.vendor` |

### TLN-001 Specific Tests

| Test case | Description |
|---|---|
| Multiple VTY ranges, all secure | All-PASS → PASS |
| First VTY secure, second VTY with telnet | Any-FAIL → FAIL |
| `transport output` + `transport input ssh` | Must not be misclassified; only `transport input` is evaluated |
| `no service telnet` global directive alone | Must **not** produce PASS — VTY transport is the definitive signal |
| Offending VTY range named in evidence | `section_name` identifies the specific failing VTY range |

### EXEC-001 Specific Tests

| Test case | Description |
|---|---|
| `exec-timeout 0 0` | Disabled → FAIL |
| `exec-timeout 10 0` | 600s → PASS |
| `exec-timeout 5 30` | 330s → PASS |
| `exec-timeout 11 0` | 660s → FAIL |
| `exec-timeout malformed` | Non-integer → NEEDS_REVIEW |
| `exec-timeout 10 foo` | Partial non-integer → NEEDS_REVIEW |
| Multiple VTY ranges | Worst-case aggregation verified |

### PWD-001 Specific Tests

| Test case | Description |
|---|---|
| Cisco `secret 9` | PASS |
| Cisco `secret 8` | PASS |
| Cisco `secret 5` (MD5) | FAIL |
| Cisco `secret 7` (reversible) | FAIL |
| Cisco `password ...` (cleartext) | FAIL |
| Cisco mixed enable items (weak + strong) | Any weak → FAIL |
| Juniper `"$6$` (SHA-512) | PASS |
| Juniper `"$5$` (SHA-256) | PASS |
| Juniper `"$1$` (MD5) | FAIL |
| Hash material in evidence `observed` | Must contain `[REDACTED]`, not actual hash |
| Hash material in evidence `raw_lines` | Must contain `[REDACTED]`, not actual hash |

### Engine Tests

| Test | Description |
|---|---|
| Empty rule list | Returns empty list |
| Multiple rules | Returns one result per rule |
| Preserves rule order | Result order matches input rule order |
| NOT_APPLICABLE in results | Counts as a result, not an error |
| SSH-001 + TLN-001 together | Both evaluated, both results returned in order |

---

## What Is Not Tested

| Gap | Notes |
|---|---|
| Integration tests (file → result) | No end-to-end pipeline test exists |
| Real device configurations | Only synthetic / fixture configs used |
| Large / complex configs | No performance or stress tests |
| AAA-001 rule | Designed but not implemented |
| Reporting / serialisation | No output layer implemented |
| Juniper vendor detection | `detect_vendor()` only detects Cisco; no test for Juniper detection |
