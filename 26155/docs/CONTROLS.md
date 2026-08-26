# PS 26155 — Implemented Security Controls

All four controls follow the same evaluation contract: deterministic input → deterministic output, mandatory evidence at every status, vendor-specific remediation on FAIL only.

---

## SSH-001 — SSH Protocol Version Must Be 2

**Control ID:** `SSH-001`  **Severity:** HIGH  **Vendors:** Cisco, Juniper  
**Framework refs:** CIS-IOS-L2-1.1.1, NIST-AC-17(2), ISO27001-A.9.4.2

### Purpose

SSH must use protocol version 2 exclusively. SSHv1 contains known cryptographic weaknesses (session injection, weak key exchange) and must not be permitted.

### Cisco Behaviour

`ip ssh version 2` is stored in `global_items` as `key="ip"`, `value="ssh version 2"`.

> Multiple `ip ...` directives share the key `"ip"`. The rule scans **all** `global_items` and filters by `key == "ip"` AND `value.startswith("ssh version")`.

| Observed | Status |
|---|---|
| `ssh version 2` | `PASS` |
| `ssh version 1` | `FAIL` |
| Directive absent | `FAIL` |
| Other value | `NEEDS_REVIEW` |

### Juniper Behaviour

`protocol-version v2;` is under `system > services > ssh`, flattened by the parser into the `system` section: `key="protocol-version"`, `value="v2"`.

| Observed | Status |
|---|---|
| `v2` | `PASS` |
| `v1` | `FAIL` |
| `protocol-version` absent (system present) | `FAIL` |
| `system` section absent | `FAIL` |
| Other value | `NEEDS_REVIEW` |

### Remediation

**Cisco:** `ip ssh version 2` — Verify with `show ip ssh`.  
**Juniper:** `set system services ssh protocol-version v2` — Verify with `show system services ssh`.

---

## TLN-001 — Telnet Must Be Disabled

**Control ID:** `TLN-001`  **Severity:** CRITICAL  **Vendors:** Cisco, Juniper  
**Framework refs:** CIS-IOS-L2-1.3.1, NIST-AC-17(2), ISO27001-A.9.4.2

### Purpose

Telnet transmits all data — including credentials — in plaintext. SSH must be the exclusive interactive management protocol.

### Cisco Behaviour

Evaluated via `transport input` inside each `line vty <range>` section. Multiple VTY ranges are all evaluated.

> `transport output` shares the key `"transport"`. The rule filters to items where `value.lower().startswith("input")`.  
> `no service telnet` global directive is **not** used as the primary signal.

| `transport input` value | Per-section result |
|---|---|
| `input ssh` | PASS |
| `input none` | PASS |
| Contains `"telnet"` | FAIL |
| `input all` | FAIL |
| Directive absent from VTY section | NEEDS_REVIEW |
| Unrecognised value | NEEDS_REVIEW |
| No `line vty` sections found | NEEDS_REVIEW |

Multi-section aggregation: **any FAIL → FAIL; no FAIL + any NEEDS_REVIEW → NEEDS_REVIEW; all PASS → PASS**.

### Juniper Behaviour

Presence/absence of `telnet;` flag under `system > services`, flattened to `system` section: `key="telnet"`, `value=None`.

| Signal | Status |
|---|---|
| `telnet` key present in system | `FAIL` |
| `telnet` key absent | `PASS` |
| `system` section absent | `FAIL` |

### Remediation

**Cisco:**
```
line vty 0 4
 transport input ssh
line vty 5 15
 transport input ssh
```
**Juniper:** `delete system services telnet`

---

## EXEC-001 — VTY Idle Session Timeout Must Be Configured

**Control ID:** `EXEC-001`  **Severity:** HIGH  **Vendors:** Cisco, Juniper  
**Framework refs:** CIS-IOS-L2-2.1.1, NIST-AC-17(2), ISO27001-A.9.4.2

### Purpose

Idle management sessions must time out within **10 minutes (600 seconds)** to reduce the risk of unauthorised access.

### Cisco Behaviour

`exec-timeout <minutes> <seconds>` inside each `line vty <range>`. Multiple VTY ranges all evaluated.

`total_seconds = minutes * 60 + seconds`

| Condition | Status |
|---|---|
| `0 < total_seconds ≤ 600` | PASS |
| `total_seconds == 0` (disabled) | FAIL |
| `total_seconds > 600` | FAIL |
| `exec-timeout` absent | NEEDS_REVIEW |
| Value present, no string | NEEDS_REVIEW |
| Not exactly two tokens | NEEDS_REVIEW |
| Cannot parse as integers | NEEDS_REVIEW |
| No `line vty` sections | NEEDS_REVIEW |

### Juniper Behaviour

`idle-timeout <minutes>;` under `system > login`, flattened to `system` section: `key="idle-timeout"`, `value="<n>"`.

| Condition | Status |
|---|---|
| `0 < minutes ≤ 10` | PASS |
| `minutes == 0` | FAIL |
| `minutes > 10` | FAIL |
| Directive absent | NEEDS_REVIEW |
| `system` section absent | NEEDS_REVIEW |
| Value None or non-integer | NEEDS_REVIEW |

### Remediation

**Cisco:** `exec-timeout 10 0` in each VTY section.  
**Juniper:** `set system login idle-timeout 10`

---

## PWD-001 — Privileged Exec / Root Password Must Use Strong Hashing

**Control ID:** `PWD-001`  **Severity:** HIGH  **Vendors:** Cisco, Juniper  
**Framework refs:** CIS-IOS-L2-2.1.1, CIS-JUNOS-L2-2.1.1

### Purpose

Detects weak or deprecated password hashing for the highest-privilege management credential. Prevents offline password cracking.

### Cisco Behaviour

Inspects all `global_items` where `key == "enable"`.

| Value prefix | Classification | Status |
|---|---|---|
| `secret 8` | PBKDF2-SHA512 | PASS |
| `secret 9` | scrypt | PASS |
| `secret 5` | MD5 | FAIL |
| `secret 7` | reversible Type 7 | FAIL |
| `secret 0` | stored cleartext | FAIL |
| `password ...` | cleartext | FAIL |
| Other / unrecognised | — | NEEDS_REVIEW |
| No `enable` directive | — | NEEDS_REVIEW |

If multiple `enable` items exist and **any** is weak → overall `FAIL`.

### Juniper Behaviour

Inspects `system` section items where `key == "encrypted-password"`.

| Value prefix | Algorithm | Status |
|---|---|---|
| `"$5$` | SHA-256 | PASS |
| `"$6$` | SHA-512 | PASS |
| `"$8$` | PBKDF2-SHA1 | PASS |
| `"$9$` | JunOS native | PASS |
| `"$1$` | MD5 | FAIL |
| Other prefix | Unknown | NEEDS_REVIEW |
| Absent / empty | — | NEEDS_REVIEW |

### Evidence Sanitization

Hash material and cleartext passwords are **always redacted** in evidence. The `raw_line` and `observed` fields have the sensitive content replaced with `[REDACTED]`. The hash algorithm prefix (e.g., `secret 9`, `"$6`) is preserved so the classification is still readable.

### Remediation

**Cisco:** "Migrate the privileged credential to a supported strong password hashing mechanism (e.g., secret 8 or 9)."  
**Juniper:** "Replace the weak root password hash with a modern supported password-hashing configuration (e.g., SHA-512)."
