# CAPEC-702 — Exploiting Incorrect Chaining or Granularity of Hardware Debug Components

<a id="capec-702"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Draft  

An adversary exploits incorrect chaining or granularity of hardware debug components in order to gain unauthorized access to debug functionality on a chip. This happens when authorization is not checked on a per function basis and is assumed for a chain or group of debug functionality.

## Related CWE (1)

- [CWE-1296 — Incorrect Chaining or Granularity of Debug Components](https://cwe.mitre.org/data/definitions/1296.html) — The product's debug components contain incorrect chaining or granularity of debug components.

## Prerequisites

- Hardware device has an exposed debug interface

## Skills required

- [Medium] Ability to identify physical debug interfaces on a device
- [Medium] Ability to operate devices to scan and connect to an exposed debug interface

## Consequences

- Confidentiality / Read Data
- Integrity / Modify Data
- Access Control, Authorization / Gain Privileges

## Mitigations

- Implement: Ensure that debug components are properly chained, and their granularity is maintained at different authorization levels
- Perform Post-silicon validation tests at various authorization levels to ensure that debug components are only accessible to authorized users

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
