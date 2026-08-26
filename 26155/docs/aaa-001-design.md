# AAA-001 Design Document
## Remote AAA Authentication Must Be Primary

**Status:** PROBE + DESIGN ONLY — No production code modified  
**Date:** 2026-08-26  
**Baseline:** 229 tests passing, `git diff --check` clean  
**Branch:** main (post-pull, commit 22e46da)

---

## Table of Contents

1. [Current Cisco Representation](#1-current-cisco-representation)
2. [Current Juniper Representation](#2-current-juniper-representation)
3. [Probe Results](#3-probe-results)
4. [Exact AAA-001 Definition](#4-exact-aaa-001-definition)
5. [PASS Conditions](#5-pass-conditions)
6. [FAIL Conditions](#6-fail-conditions)
7. [NEEDS_REVIEW Conditions](#7-needs_review-conditions)
8. [NOT_APPLICABLE Behavior](#8-not_applicable-behavior)
9. [Multi-Section Aggregation](#9-multi-section-aggregation)
10. [Evidence Design](#10-evidence-design)
11. [Remediation Design](#11-remediation-design)
12. [Architecture Sufficiency](#12-architecture-sufficiency)
13. [Edge Cases](#13-edge-cases)
14. [Test Matrix](#14-test-matrix)
15. [Implementation Plan](#15-implementation-plan)

---

## 1. Current Cisco Representation

### How the Cisco parser stores AAA configuration

All AAA directives are **global items** (non-indented, non-section-starting lines).
The Cisco `_make_item` helper splits each line on the first whitespace token only:

```
Input line:  "aaa authentication login default group radius local"
item.key   = "aaa"
item.value = "authentication login default group radius local"
```

So every `aaa ...` line, regardless of sub-command, shares `key = "aaa"`.
The complete semantic content lives exclusively in `item.value`.

### Verified by probes — complete global_items for representative cases

| Config line | `item.key` | `item.value` |
|---|---|---|
| `aaa new-model` | `"aaa"` | `"new-model"` |
| `aaa authentication login default local` | `"aaa"` | `"authentication login default local"` |
| `aaa authentication login default group radius` | `"aaa"` | `"authentication login default group radius"` |
| `aaa authentication login default local group radius` | `"aaa"` | `"authentication login default local group radius"` |
| `aaa authentication login default group tacacs+` | `"aaa"` | `"authentication login default group tacacs+"` |
| `aaa authentication login default local group tacacs+` | `"aaa"` | `"authentication login default local group tacacs+"` |
| `aaa authentication login CONSOLE local` | `"aaa"` | `"authentication login CONSOLE local"` |
| `aaa authentication login MGMT group tacacs+ local` | `"aaa"` | `"authentication login MGMT group tacacs+ local"` |
| `aaa authorization exec default local` | `"aaa"` | `"authorization exec default local"` |

### Critical API implication

`NormalizedConfig.get_global("aaa")` returns only the **first** `aaa` item — typically
`new-model`. To interrogate all AAA configuration a rule must iterate
`config.global_items` and filter by `item.key.lower() == "aaa"`.

### VTY section items (advisory signals only)

VTY sections can carry `login` or `login authentication <list-name>` items:

| Config line inside `line vty` | `item.key` | `item.value` |
|---|---|---|
| ` login local` | `"login"` | `"local"` |
| ` login authentication default` | `"login"` | `"authentication default"` |
| ` login authentication CONSOLE` | `"login"` | `"authentication CONSOLE"` |

These are **not** the primary evaluation surface for AAA-001.
The canonical AAA policy is defined at global level.

---

## 2. Current Juniper Representation

### How the Juniper parser stores AAA configuration

JunOS uses `authentication-order` under `system {}`.
The parser matches it with `_LEAF_RE` and captures the full bracket list as `item.value`:

```
Input line:  "    authentication-order [ radius password ];"
item.key   = "authentication-order"
item.value = "[ radius password ]"
```

The `system` section is accessed via `config.get_section("system")`.
Authentication-order is then found by iterating `system.items` for
`item.key.lower() == "authentication-order"`.

### Nested sub-block behaviour (IMPORTANT — verified by probe)

`radius-server {}` and `tacplus-server {}` are nested at brace-depth >= 2.
Their leaf lines are **flattened into `system.items`** with ambiguous keys:

```
system {
    radius-server {
        10.0.0.1 {
            port 1812;
            secret "$9$abc123";
        }
    }
}
```

Produces in `system.items`:

```
key="port"    value="1812"
key="secret"  value='"$9$abc123"'
```

And in Probe J9 (realistic multi-server config), server IPs appear as keys:

```
key="10.0.0.1"  value='secret "$9$xxx"'
```

These are NOT usable as reliable server-presence signals. The rule must use
`authentication-order` as the sole evaluation signal.

### JunOS token semantics

| Token in `authentication-order` value | Meaning |
|---|---|
| `radius` | RADIUS (remote) |
| `tacplus` | TACACS+ (remote) |
| `password` | Local password (local) |

The **first token** after stripping `[` `]` is the **primary authentication method**.

---

## 3. Probe Results

### Cisco Probes (11 cases)

#### A — `aaa new-model` only
```
global_items:
  key='aaa'  value='new-model'
sections: []
```
Signal: AAA framework active. No authentication method list configured.

---

#### B — `aaa authentication login default local`
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default local'
sections: []
```
Signal: Default list — local only. Remote is not primary.

---

#### C — `aaa authentication login default group radius`
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default group radius'
sections: []
```
Signal: Remote RADIUS is primary. No local fallback.

---

#### D — `aaa authentication login default local group radius`
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default local group radius'
sections: []
```
Signal: Local is primary, RADIUS is fallback. Non-compliant.

---

#### E — `aaa authentication login default group tacacs+`
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default group tacacs+'
sections: []
```
Signal: Remote TACACS+ is primary. Compliant.

---

#### F — `aaa authentication login default local group tacacs+`
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default local group tacacs+'
sections: []
```
Signal: Local is primary, TACACS+ is fallback. Non-compliant.

---

#### G — Multiple authentication lists
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default group radius local'
  key='aaa'  value='authentication login CONSOLE local'
  key='aaa'  value='authentication login MGMT group tacacs+ local'
sections: []
```
Signal: Three lists present. Default is remote-primary (PASS). Named lists
CONSOLE and MGMT are not AAA-001's evaluation target.

---

#### H — `aaa new-model` with no authentication list (only authorization)
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authorization exec default local'
sections: []
```
Signal: AAA active but no `authentication login` list configured. FAIL.

---

#### I — VTY `login local` (no `aaa new-model`)
```
global_items:
  key='hostname'  value='Router'
sections:
  [section] name='line vty 0 4'
    key='login'      value='local'
    key='transport'  value='input ssh'
```
Signal: AAA framework NOT active. Legacy `login local`. FAIL.

---

#### J — VTY `login authentication default` (with `aaa new-model` + RADIUS default)
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default group radius local'
sections:
  [section] name='line vty 0 4'
    key='login'      value='authentication default'
    key='transport'  value='input ssh'
```
Signal: Default list is remote-primary. VTY explicitly uses it. PASS.

---

#### K — Multiple VTY sections with different auth policies
```
global_items:
  key='aaa'  value='new-model'
  key='aaa'  value='authentication login default group radius local'
  key='aaa'  value='authentication login CONSOLE local'
sections:
  [section] name='line vty 0 4'
    key='login'  value='authentication default'    <- compliant default
  [section] name='line vty 5 15'
    key='login'  value='authentication CONSOLE'    <- local-only bypass
```
Signal: Default list is remote-primary (PASS). VTY 5-15 uses CONSOLE (local-only bypass).
AAA-001 verdict: PASS. Advisory Evidence note emitted for VTY 5-15.

---

### Juniper Probes (9 cases)

#### J1 — `authentication-order [ password radius ]`
```
system.items:
  key='authentication-order'  value='[ password radius ]'
```
Signal: Local is first. Non-compliant.

---

#### J2 — `authentication-order [ radius password ]`
```
system.items:
  key='authentication-order'  value='[ radius password ]'
```
Signal: RADIUS is primary. Compliant.

---

#### J3 — `authentication-order [ tacplus password ]`
```
system.items:
  key='authentication-order'  value='[ tacplus password ]'
```
Signal: TACACS+ is primary. Compliant.

---

#### J4 — `authentication-order [ password ]` (local only)
```
system.items:
  key='authentication-order'  value='[ password ]'
```
Signal: Local only. Non-compliant.

---

#### J5 — `radius-server` block + `authentication-order [ radius password ]`
```
system.items:
  key='authentication-order'  value='[ radius password ]'
  key='port'                  value='1812'
  key='secret'                value='"$9$abc123"'
```
Signal: authentication-order is the evaluation signal. port/secret from
radius-server sub-block are noise — do not use them.

---

#### J6 — `tacplus-server` block + `authentication-order [ tacplus password ]`
```
system.items:
  key='authentication-order'  value='[ tacplus password ]'
  key='port'                  value='49'
  key='secret'                value='"$9$def456"'
```
Signal: Same pattern. TACACS+ primary. Compliant.

---

#### J7 — `authentication-order` absent (system section exists)
```
system.items:
  key='host-name'           value='SRX-LAB'
  key='encrypted-password'  value='"$6$hash"'
```
Signal: No authentication-order item. Cannot confirm remote auth. FAIL.

---

#### J8 — System block absent entirely
```
sections:
  [section] name='interfaces'
    key='address'  value='192.168.1.1/24'
```
Signal: No system section. No auth config extractable. FAIL.

---

#### J9 — Full realistic system block (multi-server)
```
system.items:
  key='host-name'             value='SRX-PROD'
  key='authentication-order'  value='[ radius tacplus password ]'
  key='10.0.0.1'              value='secret "$9$xxx"'    <- noise from sub-block
  key='10.0.0.2'              value='secret "$9$yyy"'    <- noise
  key='10.0.0.3'              value='secret "$9$zzz"'    <- noise
  key='idle-timeout'          value='10'
```
Signal: RADIUS primary, TACACS+ secondary, local fallback. Compliant.
Server IP entries as keys are parser artefacts — must not be used as signals.

---

## 4. Exact AAA-001 Definition

### Control Metadata

```python
SecurityControl(
    control_id="AAA-001",
    control_name="Remote AAA Authentication Must Be Primary",
    description=(
        "Centralized (remote) AAA enforces consistent access control, enables "
        "real-time audit logging, supports role-based access control, and allows "
        "immediate credential revocation. When local authentication is primary, "
        "none of these properties hold. This control verifies that a remote AAA "
        "method (RADIUS or TACACS+) is the first (primary) method in the default "
        "authentication list for management access."
    ),
    severity=Severity.HIGH,
    framework_refs=("CIS-IOS-L2-1.4.1", "NIST-IA-2(1)", "ISO27001-A.9.4.2"),
    applicable_vendors=frozenset({"cisco", "juniper"}),
)
```

### Evaluated security property

**NOT:** "Does AAA exist?"

**YES:** "Is remote/centralized authentication the PRIMARY method in the default
management authentication policy?"

A local fallback is acceptable and recommended. What is not acceptable is local
being primary — because that means every authentication attempt goes to local
credentials first, bypassing centralized audit and revocation until the remote
server fails.

### Extraction strategy (no `raw_line` parsing)

**Cisco:**
1. Scan `config.global_items` for `item.key.lower() == "aaa"`.
2. Check for `value == "new-model"` (AAA active).
3. Find items where `value.lower().startswith("authentication login default ")`.
4. Extract suffix: `value[len("authentication login default "):].strip()`.
5. Classify suffix's first method token.

**Juniper:**
1. `system = config.get_section("system")`.
2. Find `item.key.lower() == "authentication-order"`.
3. Parse value: strip `[` `]`, split on whitespace, inspect first token.

Both use only `ConfigItem.value` — no regex or raw_line access.

---

## 5. PASS Conditions

### Cisco — PASS

All must hold:

1. `aaa new-model` is present (key=`"aaa"`, value=`"new-model"`).
2. Exactly one global item with `value.lower().startswith("authentication login default ")`.
3. The suffix after `"authentication login default "` begins with `"group "` (remote).

Compliant examples:
- `"authentication login default group radius"` → PASS
- `"authentication login default group tacacs+"` → PASS
- `"authentication login default group radius local"` → PASS
- `"authentication login default group tacacs+ local"` → PASS
- `"authentication login default group MYGROUP local"` → PASS (named group treated as remote)
- `"authentication login default group radius group tacacs+ local"` → PASS

### Juniper — PASS

1. `system` section exists.
2. `authentication-order` item exists in `system.items`.
3. First non-bracket token of `item.value` is `"radius"` or `"tacplus"`.

Compliant examples:
- `"[ radius password ]"` → PASS
- `"[ tacplus password ]"` → PASS
- `"[ radius tacplus password ]"` → PASS
- `"[ tacplus ]"` → PASS (remote-only, no fallback — still compliant)
- `"[ radius ]"` → PASS (remote-only)

---

## 6. FAIL Conditions

### Cisco — FAIL

**F-C1 — `aaa new-model` absent:**
AAA framework not enabled. Device uses legacy `login`/`login local`.
Evidence: absence of any item with value `"new-model"`.

**F-C2 — No `authentication login default` list (but `aaa new-model` present):**
IOS default with no list configured is platform-dependent; cannot be treated as
safe. FAIL.

**F-C3 — Default list present but local is primary:**
- `"authentication login default local"` → FAIL
- `"authentication login default local group radius"` → FAIL
- `"authentication login default local group tacacs+"` → FAIL

**F-C4 — Default list uses `none`:**
- `"authentication login default none"` → FAIL (open access — no authentication)

### Juniper — FAIL

**F-J1 — `system` section absent:**
Cannot confirm any AAA is configured. FAIL.

**F-J2 — `authentication-order` item absent (system exists):**
JunOS default when unset is local password only. FAIL.

**F-J3 — First token of `authentication-order` is `password`:**
- `"[ password ]"` → FAIL
- `"[ password radius ]"` → FAIL

**F-J4 — `authentication-order` value is clearly disabled or empty:**
Any value unambiguously indicating no remote method → FAIL.

---

## 7. NEEDS_REVIEW Conditions

### Cisco — NEEDS_REVIEW

**NR-C1 — Unrecognized primary method token:**
Suffix does not begin with `"group "`, `"local"`, or `"none"`.
Example: `"authentication login default krb5 local"`.

**NR-C2 — `item.value` is `None` for the default-list item:**
Malformed parse result. Cannot classify.

**NR-C3 — Multiple `authentication login default` items found:**
More than one default list definition (malformed/truncated config).
Cannot safely determine which is authoritative.

### Juniper — NEEDS_REVIEW

**NR-J1 — `authentication-order` item exists but `item.value` is `None`.**

**NR-J2 — `authentication-order` value does not contain recognizable `[ ]` structure.**
Example: value is `"radius"` without brackets. Parser may produce this on unusual
formatting.

**NR-J3 — `authentication-order` value's first token is unrecognized.**
Example: `"[ kerberos password ]"`. `kerberos` is not in `{radius, tacplus, password}`.

---

## 8. NOT_APPLICABLE Behavior

Control applies to `frozenset({"cisco", "juniper"})`. All other vendor strings
(e.g. `"arista"`, `"paloalto"`, `""`, `"CISCO"`) trigger `_not_applicable()`.

Result:
- `status = ComplianceStatus.NOT_APPLICABLE`
- Single `Evidence` with `note = "Control 'AAA-001' does not apply to vendor '<vendor>'."`
- No remediation.

Note: `applies_to()` is case-sensitive. The parser sets `vendor="cisco"` (lowercase).
A config with `vendor="CISCO"` would receive NOT_APPLICABLE — but this cannot occur
from the current parsers.

---

## 9. Multi-Section Aggregation

### Cisco

The primary evaluation surface is a **single global item** (`aaa authentication login default ...`).
Aggregation over multiple VTY sections is NOT performed for the primary verdict.

**Advisory VTY-binding analysis:**
When a VTY section's `login authentication <name>` references a named list that is
local-only, the device has a real bypass. This is documented in a supplementary
Evidence record (advisory, no verdict change) and deferred to a future `AAA-002` control.

**Named-list bypass rule:**
AAA-001 does NOT fail a device because VTY 5-15 uses a local-only named list.
It DOES emit an advisory Evidence note identifying the affected VTY section and
the named list value.

### Juniper

Single `authentication-order` directive. No aggregation needed.

### Aggregation decision table

| Scenario | Verdict |
|---|---|
| Remote primary, no fallback | PASS |
| Remote primary, local fallback | PASS |
| Local primary, remote fallback | FAIL |
| Local only | FAIL |
| No auth list / no auth-order | FAIL |
| No `aaa new-model` (Cisco) | FAIL |
| No system section (Juniper) | FAIL |
| Unrecognized primary method | NEEDS_REVIEW |
| Malformed value | NEEDS_REVIEW |
| Other vendor | NOT_APPLICABLE |

---

## 10. Evidence Design

Evidence uses the existing `Evidence` dataclass. No modifications required.

### Cisco evidence — PASS (remote primary + local fallback)

```python
Evidence(
    control_id="AAA-001",
    section_name=None,                     # global items have no section
    raw_lines=(
        "aaa new-model",
        "aaa authentication login default group radius local",
    ),
    observed="authentication login default group radius local",
    expected="Remote method (group radius/tacacs+) as first in default list",
    note=(
        "AAA is active ('aaa new-model' present). The default authentication "
        "list places 'group radius' as the primary method with 'local' as an "
        "explicit fallback. Control satisfied."
    ),
)
```

### Cisco evidence — FAIL (`aaa new-model` absent)

```python
Evidence(
    control_id="AAA-001",
    section_name=None,
    raw_lines=(),
    observed=None,
    expected="aaa new-model + authentication login default group <remote>",
    note=(
        "'aaa new-model' is absent. The AAA framework is not enabled. "
        "The device uses legacy login methods without centralized AAA control."
    ),
)
```

### Cisco evidence — FAIL (local is primary)

```python
Evidence(
    control_id="AAA-001",
    section_name=None,
    raw_lines=(
        "aaa new-model",
        "aaa authentication login default local group radius",
    ),
    observed="authentication login default local group radius",
    expected="Remote method (group radius/tacacs+) as first in default list",
    note=(
        "AAA is active but the default list places 'local' as the primary method. "
        "Remote RADIUS is only a fallback. Centralized authentication is bypassed "
        "for every login unless the RADIUS server is unreachable."
    ),
)
```

### Cisco advisory evidence — VTY bypass (supplementary, non-verdict-changing)

```python
Evidence(
    control_id="AAA-001",
    section_name="line vty 5 15",
    raw_lines=(" login authentication CONSOLE",),
    observed="login authentication CONSOLE",
    expected="login authentication default (or the default list applied implicitly)",
    note=(
        "[ADVISORY] VTY section 'line vty 5 15' uses named list 'CONSOLE' "
        "which may not enforce remote authentication. "
        "This does not affect the AAA-001 verdict (which evaluates the default "
        "list definition only). Review with AAA-002 when implemented."
    ),
)
```

### Juniper evidence — PASS

```python
Evidence(
    control_id="AAA-001",
    section_name="system",
    raw_lines=("    authentication-order [ radius password ];",),
    observed="authentication-order [ radius password ]",
    expected="Remote method (radius/tacplus) as first token",
    note=(
        "'radius' is the primary authentication method. "
        "Local 'password' is an explicit fallback. Control satisfied."
    ),
)
```

### Juniper evidence — FAIL (`[ password radius ]`)

```python
Evidence(
    control_id="AAA-001",
    section_name="system",
    raw_lines=("    authentication-order [ password radius ];",),
    observed="authentication-order [ password radius ]",
    expected="Remote method (radius/tacplus) as first token",
    note=(
        "Local 'password' is the primary authentication method. "
        "RADIUS is a fallback. Centralized authentication is bypassed "
        "on every login unless the remote server is unreachable."
    ),
)
```

### Juniper evidence — FAIL (system absent)

```python
Evidence(
    control_id="AAA-001",
    section_name=None,
    raw_lines=(),
    observed=None,
    expected="system { authentication-order [ radius|tacplus ... ]; }",
    note=(
        "No 'system' configuration block was found. "
        "Cannot extract any authentication configuration."
    ),
)
```

---

## 11. Remediation Design

### Cisco Remediation

```python
Remediation(
    vendor="cisco",
    guidance=(
        "Enable the AAA framework with 'aaa new-model'. "
        "Configure a default authentication list that places a remote AAA "
        "server group (RADIUS or TACACS+) as the primary method. "
        "A local fallback is recommended but must not be the primary method. "
        "Ensure all VTY lines use 'login authentication default' or an "
        "equivalent list that enforces remote-primary authentication."
    ),
    config_hint=(
        "aaa new-model\n"
        "aaa group server radius RADIUS-SERVERS\n"
        " server-private 10.0.0.1 auth-port 1812 acct-port 1813 key <key>\n"
        "aaa authentication login default group RADIUS-SERVERS local\n"
        "!\n"
        "line vty 0 4\n"
        " login authentication default\n"
        " transport input ssh"
    ),
)
```

### Juniper Remediation

```python
Remediation(
    vendor="juniper",
    guidance=(
        "Configure 'authentication-order' under 'system' to list a remote "
        "authentication method (radius or tacplus) as the first entry. "
        "A local password fallback is acceptable as a subsequent entry. "
        "Ensure the corresponding radius-server or tacplus-server block is "
        "also configured under 'system'."
    ),
    config_hint=(
        "set system authentication-order [ radius password ]\n"
        "set system radius-server <ip> secret <secret>\n"
        "# OR for TACACS+:\n"
        "set system authentication-order [ tacplus password ]\n"
        "set system tacplus-server <ip> secret <secret>"
    ),
)
```

Remediation is returned only when `status != PASS`. It is advisory only and must
never be applied automatically (consistent with the project-wide `config_hint` policy).

---

## 12. Architecture Sufficiency

> **Conclusion: NO ARCHITECTURAL CHANGES REQUIRED.**

### Component assessment

| Component | Required by AAA-001 | Currently available | Notes |
|---|---|---|---|
| `NormalizedConfig.global_items` | Iterate all `aaa` items | YES | All `aaa` lines land here |
| `NormalizedConfig.sections` | Read VTY sections for advisory | YES | Correctly captured |
| `ConfigItem.key` | Filter by `"aaa"` | YES | Always `"aaa"` |
| `ConfigItem.value` | Parse method-list string | YES | Full value string; `.startswith()` / `.split()` sufficient |
| `ConfigItem.raw_line` | Populate `Evidence.raw_lines` | YES | Preserved exactly |
| `config.get_section("system")` | Access Juniper system section | YES | Works correctly |
| `ComplianceRule._not_applicable()` | Vendor guard | YES | Inherited |
| `ComplianceRule._build_result()` | Result construction | YES | Inherited |
| `Evidence` | All required fields | YES | No new fields needed |
| `Remediation` | Vendor-specific hint | YES | `config_hint` field available |
| `ComplianceStatus` | PASS/FAIL/NEEDS_REVIEW/NOT_APPLICABLE | YES | All four values exist |
| `engine.audit()` | Auto-invocation | YES | No changes needed |

### Why no parser changes are needed

The Cisco parser correctly extracts the full `aaa authentication login default ...`
value into a single `ConfigItem.value`. The `_make_item` split-on-first-whitespace
approach preserves the entire method-list string.

The Juniper `_LEAF_RE` regex correctly captures the bracket list
`[ radius password ]` as the complete value of `authentication-order`.

### Why no NormalizedConfig changes are needed

`NormalizedConfig` already exposes `global_items` (list), `sections` (list), and
`get_section()`. The AAA rule can find everything it needs through these interfaces.

---

## 13. Edge Cases

| # | Scenario | Cisco verdict | Juniper verdict |
|---|---|---|---|
| EC-01 | Remote auth only (no local fallback) | PASS | PASS |
| EC-02 | Local auth only | FAIL | FAIL |
| EC-03 | Remote primary + local fallback | PASS | PASS |
| EC-04 | Local primary + remote fallback | FAIL | FAIL |
| EC-05 | AAA enabled, no auth method list | FAIL | n/a |
| EC-06 | `authentication-order` absent (system exists) | n/a | FAIL |
| EC-07 | Compliant default + VTY using local-only named list | PASS + advisory Evidence | n/a |
| EC-08 | Non-compliant default + VTY using remote named list | FAIL | n/a |
| EC-09 | `aaa new-model` absent (legacy login local on VTY) | FAIL | n/a |
| EC-10 | `authentication login default none` | FAIL | n/a |
| EC-11 | Named server group (`group MYGROUP`) as primary | PASS (treated remote) | n/a |
| EC-12 | Multiple `authentication login default` items | NEEDS_REVIEW | n/a |
| EC-13 | `item.value` is `None` (malformed) | NEEDS_REVIEW | NEEDS_REVIEW |
| EC-14 | Unrecognized primary method (`krb5`, `kerberos`) | NEEDS_REVIEW | NEEDS_REVIEW |
| EC-15 | `authentication-order` without `[ ]` brackets | n/a | NEEDS_REVIEW |
| EC-16 | System section absent | n/a | FAIL |
| EC-17 | Unsupported vendor | NOT_APPLICABLE | NOT_APPLICABLE |
| EC-18 | Empty config (no lines) | FAIL | FAIL |
| EC-19 | RADIUS + TACACS+ both remote, RADIUS first | PASS | PASS |
| EC-20 | TACACS+ primary, no fallback | PASS | PASS |

### Should one bad VTY block fail the device? (vs TLN-001/EXEC-001 pattern)

**No.** AAA-001 evaluates the **default authentication list definition** (global policy),
not per-VTY policy application. This is intentionally different from TLN-001/EXEC-001
where the VTY transport and timeout ARE the primary evaluation surface.

The VTY-bypass gap (Probe K: VTY 5-15 using local-only named list) is real but is
documented as advisory Evidence only. A dedicated `AAA-002` control should address
named-list VTY binding analysis as a separate, future control.

---

## 14. Test Matrix

### Cisco Test Cases (20 total)

| Test ID | Configuration | Expected Status | Evidence count |
|---|---|---|---|
| TC-C01 | `aaa new-model` + `default group radius` | PASS | 1 |
| TC-C02 | `aaa new-model` + `default group tacacs+` | PASS | 1 |
| TC-C03 | `aaa new-model` + `default group radius local` | PASS | 1 |
| TC-C04 | `aaa new-model` + `default group tacacs+ local` | PASS | 1 |
| TC-C05 | `aaa new-model` + `default group MYGROUP local` | PASS | 1 |
| TC-C06 | `aaa new-model` + `default local` | FAIL | 1 |
| TC-C07 | `aaa new-model` + `default local group radius` | FAIL | 1 |
| TC-C08 | `aaa new-model` + `default local group tacacs+` | FAIL | 1 |
| TC-C09 | `aaa new-model` + `default none` | FAIL | 1 |
| TC-C10 | `aaa new-model`, no default list (only authz) | FAIL | 1 |
| TC-C11 | No `aaa new-model`, no VTY | FAIL | 1 |
| TC-C12 | No `aaa new-model`, VTY `login local` | FAIL | 1 |
| TC-C13 | `aaa new-model` + `default` with `value=None` (synthetic) | NEEDS_REVIEW | 1 |
| TC-C14 | `aaa new-model` + `default krb5 local` | NEEDS_REVIEW | 1 |
| TC-C15 | Two `authentication login default` items | NEEDS_REVIEW | 1 |
| TC-C16 | Multiple lists, default=`group radius local` | PASS | 1 |
| TC-C17 | Multiple lists, default=`local` | FAIL | 1 |
| TC-C18 | Compliant default + VTY using named local-only list (Probe K) | PASS | 2 (1 primary + 1 advisory) |
| TC-C19 | `default group radius group tacacs+ local` | PASS | 1 |
| TC-C20 | Empty config `""` | FAIL | 1 |

### Juniper Test Cases (15 total)

| Test ID | Configuration | Expected Status | Evidence count |
|---|---|---|---|
| TC-J01 | `authentication-order [ radius password ]` | PASS | 1 |
| TC-J02 | `authentication-order [ tacplus password ]` | PASS | 1 |
| TC-J03 | `authentication-order [ radius tacplus password ]` | PASS | 1 |
| TC-J04 | `authentication-order [ tacplus ]` (no fallback) | PASS | 1 |
| TC-J05 | `authentication-order [ radius ]` (no fallback) | PASS | 1 |
| TC-J06 | `authentication-order [ password ]` | FAIL | 1 |
| TC-J07 | `authentication-order [ password radius ]` | FAIL | 1 |
| TC-J08 | `authentication-order [ password tacplus ]` | FAIL | 1 |
| TC-J09 | `authentication-order` absent (system exists) | FAIL | 1 |
| TC-J10 | System section absent | FAIL | 1 |
| TC-J11 | `authentication-order` item with `value=None` (synthetic) | NEEDS_REVIEW | 1 |
| TC-J12 | `authentication-order [ kerberos ]` | NEEDS_REVIEW | 1 |
| TC-J13 | `authentication-order` value without brackets (synthetic) | NEEDS_REVIEW | 1 |
| TC-J14 | Empty config `""` | FAIL | 1 |
| TC-J15 | Full realistic: `[ radius tacplus password ]` + server items | PASS | 1 |

### Cross-Vendor Tests (5 total)

| Test ID | Scenario | Expected Status |
|---|---|---|
| TC-XV01 | `vendor="arista"` | NOT_APPLICABLE |
| TC-XV02 | `vendor="paloalto"` | NOT_APPLICABLE |
| TC-XV03 | `vendor=""` (empty string) | NOT_APPLICABLE |
| TC-XV04 | PASS result has evidence list, empty remediations | PASS (field check) |
| TC-XV05 | FAIL result has non-empty remediations | FAIL (field check) |

**Total: 40 test cases**

---

## 15. Implementation Plan

### Pre-conditions (already satisfied)

- [x] Parsers produce correct normalized representation (verified by probes above)
- [x] NormalizedConfig, Evidence, Remediation, ComplianceStatus all sufficient
- [x] No architectural changes required
- [x] 229 existing tests pass, `git diff --check` clean

### Phase 1 — Test file (TDD red)

**New file:** `26155/tests/unit/test_aaa_rule.py`

- 40 test cases from matrix above
- Parametrize Cisco and Juniper groups with `pytest.mark.parametrize`
- Import `AaaRule` from the future `aaa.py`
- Run: expect 40 new failures

### Phase 2 — Rule implementation

**New file:** `26155/src/compliance/rules/aaa.py`

Structure (mirrors `telnet_disabled.py` / `pwd_encryption.py`):

```
Module docstring (control semantics, vendor extraction notes)

_CONTROL = SecurityControl(...)
_CISCO_REMEDIATION = Remediation(vendor="cisco", ...)
_JUNIPER_REMEDIATION = Remediation(vendor="juniper", ...)

_SEC_PASS = "pass"
_SEC_FAIL = "fail"
_SEC_NEEDS_REVIEW = "needs_review"

# Private helpers
def _has_aaa_new_model(global_items) -> bool
def _find_default_auth_lists(global_items) -> list[ConfigItem]
def _classify_cisco_default_list(value: str) -> str   # _SEC_* sentinel
def _classify_juniper_auth_order(value: str) -> str   # _SEC_* sentinel
def _find_vty_named_list_bypasses(sections, default_value) -> list[Evidence]

class AaaRule(ComplianceRule):
    control = _CONTROL

    def evaluate(self, config) -> ComplianceResult
    def _evaluate_cisco(self, config) -> ComplianceResult
    def _evaluate_juniper(self, config) -> ComplianceResult
```

### Phase 3 — Verification

```bash
python -m pytest 26155/tests/unit/ -q
# Expected: 229 + 40 = 269 tests passing, 0 failed

git diff --check
# Expected: exit 0, no output
```

### Estimated effort

| Task | Estimate |
|---|---|
| Test file (40 cases, parametrized) | 2-3 hours |
| Rule implementation | 2-3 hours |
| Review and edge-case refinement | 1 hour |
| **Total** | **5-7 hours** |

### Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Named-list VTY bypass produces false PASS | Medium | Document as known gap; emit advisory Evidence; defer to AAA-002 |
| `group <named-server-group>` misclassified as local | Low | Any suffix starting with `"group "` is treated as remote |
| JunOS `authentication-order` without `[ ]` | Low | Covered in TC-J13; value string check before bracket parse |
| `aaa new-model` absent but VTY has `login authentication` | Very low | VTY `login authentication` without `new-model` is a config error; rule correctly FAILs on missing `new-model` |
| Multiple default lists (truncated config) | Very low | Covered in TC-C15; NEEDS_REVIEW with explanatory note |

---

## Appendix A — Parser Behaviour Summary for AAA

### Cisco `parse_cisco`

- `aaa new-model` → `ConfigItem(key="aaa", value="new-model")`
- `aaa authentication login default group radius local` → `ConfigItem(key="aaa", value="authentication login default group radius local")`
- **All `aaa` lines are global items.** `_SECTION_STARTERS` does not include `aaa`. Correct by design.
- `get_global("aaa")` returns only the first `aaa` item. The rule must iterate `config.global_items` directly.

### Juniper `parse_juniper`

- `authentication-order [ radius password ];` → matched by `_LEAF_RE` as `key="authentication-order"`, `value="[ radius password ]"`.
- `radius-server {}` / `tacplus-server {}` leaf lines are flattened into `system.items` at brace-depth >= 2. Their keys (`port`, `secret`, IP addresses) are parser artefacts, NOT reliable server-presence signals.
- `authentication-order` is the only signal the rule should use.

---

## Appendix B — Baseline Validation

```
$ python -m pytest 26155/tests/unit/ -q
229 passed in 0.74s

$ git diff --check
(exit 0, no output)
```

No existing tests modified.  
No production source code modified.  
No commits made.

---

*END OF DESIGN DOCUMENT — STOP. DO NOT IMPLEMENT AAA-001.*
