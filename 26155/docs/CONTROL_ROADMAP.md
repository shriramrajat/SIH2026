# Control Expansion Roadmap

## 1. Current Control Coverage

The current architecture demonstrates the following capabilities through SSH-001, TLN-001, and EXEC-001:

- **Exact value comparison:** Validating SSH version string.
- **Presence/absence:** Verifying `transport input` directives and SSH services.
- **Multi-section evaluation:** Evaluating all Cisco `line vty` sections and aggregating the result (failing the device if any section fails).
- **Numeric threshold evaluation:** Comparing timeout minutes/seconds against mathematical thresholds.
- **Malformed input handling:** Safely falling back to `NEEDS_REVIEW` when values cannot be cast to integers.
- **NEEDS_REVIEW:** Flagging ambiguous or malformed configurations for manual inspection.
- **NOT_APPLICABLE:** Safely bypassing unsupported vendors (e.g., Arista) at the rule level.
- **Evidence:** Capturing precise `ConfigSection` names and `raw_line` snippets.
- **Remediation:** Providing vendor-specific actionable remediation text.

---

## 2. Candidate Controls

The following candidates were selected based on the extraction capabilities of the *current* Cisco and Juniper parsers.

1. **PWD-001 — Privileged Exec / Root Password Must Use Strong Hashing**
   - **Security purpose:** Prevent offline password cracking of the highest privileged account.
   - **Cisco rep:** `global_item` with key `enable`.
   - **Juniper rep:** `ConfigItem` with key `encrypted-password` in the `system` section.
2. **AAA-001 — Remote AAA Authentication Must Be Primary**
   - **Security purpose:** Enforce centralized identity management.
   - **Cisco rep:** `global_item` with key `aaa`.
   - **Juniper rep:** `ConfigItem` with key `authentication-order` in the `system` section.
3. **SSH-002 — SSH Authentication Retries Must Be Limited**
   - **Security purpose:** Prevent SSH brute-forcing.
   - **Cisco rep:** `global_item` with key `ip` (value starting with `ssh authentication-retries`).
   - **Juniper rep:** `ConfigItem` with key `connection-limit` in the `system` section.
4. **TIME-001 — Timezone Must Be UTC**
   - **Security purpose:** Ensure globally consistent log correlation.
   - **Cisco rep:** `global_item` with key `clock`.
   - **Juniper rep:** `ConfigItem` with key `time-zone` in the `system` section.
5. **SVC-001 — HTTP Management Must Be Disabled**
   - **Security purpose:** Prevent unencrypted management access.
   - **Cisco rep:** `global_item` with key `no` (value `ip http server`).
   - **Juniper rep:** Absence of `web-management` items.
6. **DNS-001 — IP Domain Lookup Must Be Disabled**
   - **Security purpose:** Prevent DNS spoofing and accidental resolution delays.
   - **Cisco rep:** `global_item` with key `no` (value `ip domain-lookup`).
   - **Juniper rep:** N/A (differing vendor semantics).
7. **NTP-001 — NTP Server Must Be Configured**
   - **Security purpose:** Accurate time synchronization.
   - **Cisco rep:** `global_item` with key `ntp`.
   - **Juniper rep:** `ConfigItem` with key `server` in `system`. (Highly ambiguous due to Juniper parser flattening, as it overlaps with DNS `name-server`).

---

## 3. Scoring Table

| Candidate | Security Value (1-5) | POC Demo Value (1-5) | Cross-Vendor (1-5) | Deterministic (1-5) | Evidence Quality (1-5) | Implementation Difficulty (1-5) | Total |
|-----------|----------------------|----------------------|--------------------|---------------------|------------------------|---------------------------------|-------|
| PWD-001   | 5                    | 5                    | 5                  | 5                   | 5                      | 2 (Easy)                        | 27    |
| AAA-001   | 5                    | 4                    | 5                  | 4                   | 5                      | 3 (Moderate)                    | 26    |
| TIME-001  | 3                    | 3                    | 5                  | 5                   | 5                      | 1 (Easy)                        | 22    |
| SSH-002   | 4                    | 4                    | 4                  | 5                   | 5                      | 3 (Moderate)                    | 25    |
| SVC-001   | 4                    | 4                    | 3                  | 4                   | 4                      | 3 (Moderate)                    | 22    |
| DNS-001   | 2                    | 2                    | 1 (Cisco Only)     | 5                   | 5                      | 1 (Easy)                        | 16    |
| NTP-001   | 4                    | 3                    | 2 (Juniper Ambig.) | 3                   | 2                      | 4 (Hard)                        | 18    |

---

## 4. Recommended Next 3 Controls

1. **#1 — PWD-001 (Privileged Exec / Root Password Must Use Strong Hashing)**: Highest overall score. Introduces a new evaluation pattern (structured string prefix matching for hash types) while remaining 100% deterministic and cross-vendor.
2. **#2 — AAA-001 (Remote AAA Authentication Must Be Primary)**: Tests substring matching across completely different vendor string structures (`aaa authentication login default group radius` vs `authentication-order [ radius ]`).
3. **#3 — SSH-002 (SSH Authentication Retries Must Be Limited)**: Expands numeric thresholding to global values instead of just block section values.

---

## 5. Detailed Design of Control #4 (PWD-001)

### Control Details
- **Control ID:** PWD-001
- **Control Name:** Privileged Exec / Root Password Must Use Strong Hashing
- **Security Purpose:** Prevent offline cracking of the highest privileged account using deprecated hashing algorithms like MD5 or DES.

### Semantics
- **Cisco:**
  - Evaluates `global_item` where key == `enable`.
  - **PASS:** Value starts with `secret 5`, `secret 8`, or `secret 9`.
  - **FAIL:** Value starts with `password` (cleartext/type 7) or `secret 0`.
  - **NEEDS_REVIEW:** Value is malformed or ambiguous.
- **Juniper:**
  - Evaluates `ConfigItem` where key == `encrypted-password` in the `system` section.
  - **PASS:** Value starts with `"$5$"` or `"$6$"` (SHA-256/SHA-512) or `"$8$"` / `"$9$"`.
  - **FAIL:** Value starts with `"$1$"` (MD5) or doesn't have a recognizable strong prefix.
  - **NEEDS_REVIEW:** Value is malformed or ambiguous.

---

## 6. Probe Results for PWD-001

Probes were run against the foundation parsers to verify the exact structural representation of edge cases.

### Cisco Results
- **Compliant (`enable secret 9 $9$...`):** Key: `enable` \| Value: `secret 9 $9$somehash` \| Raw: `enable secret 9 $9$somehash`
- **Non-Compliant MD5 (`enable secret 5 $1$...`):** Key: `enable` \| Value: `secret 5 $1$somehash` \| Raw: `enable secret 5 $1$somehash`
- **Non-Compliant Cleartext (`enable password ...`):** Key: `enable` \| Value: `password cleartext` \| Raw: `enable password cleartext`
- **Ambiguous (`enable foo bar`):** Key: `enable` \| Value: `foo bar`
- **Missing (`hostname R1` only):** Successfully detected as missing `enable` directive.
- **Multiple (`enable password ...` + `enable secret ...`):** Both items are extracted as distinct global items. The rule must evaluate the strongest configured, or fail if a weak one exists.

### Juniper Results
- **Compliant (`encrypted-password "$6$..."`):** Key: `encrypted-password` \| Value: `"$6$somehash"` \| Raw: `encrypted-password "$6$somehash";`
- **Non-Compliant MD5 (`encrypted-password "$1$..."`):** Key: `encrypted-password` \| Value: `"$1$somehash"`
- **Ambiguous (`encrypted-password;`):** Key: `encrypted-password` \| Value: `None`
- **Missing:** Successfully detected as missing `encrypted-password` item.

---

## 7. Architecture Impact

**NO ARCHITECTURAL CHANGES REQUIRED.**

PWD-001 can be implemented purely as a new `ComplianceRule` inheriting from the base class.
- The parsers correctly extract the required lines without dropping the hash prefixes.
- `NormalizedConfig` natively exposes `get_global("enable")` and `get_section("system")`.
- `ComplianceResult` and `Evidence` can natively handle the output.
- The compliance engine will automatically discover and run it once added to the `rules/` directory.

---

## 8. Proposed Implementation Order

1. Create `tests/unit/test_pwd_encryption_rule.py` with TDD fixtures for all Cisco and Juniper boundary conditions.
2. Create `src/compliance/rules/pwd_encryption.py`.
3. Implement `_evaluate_cisco()`.
4. Implement `_evaluate_juniper()`.
5. Run full test suite to confirm 200 + new tests pass.
