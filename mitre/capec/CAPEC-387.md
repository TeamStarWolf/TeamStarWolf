# CAPEC-387 — Navigation Remapping To Propagate Malicious Content

<a id="capec-387"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An adversary manipulates either egress or ingress data from a client within an application framework in order to change the content of messages and thereby circumvent the expected application logic.

## Related CWE (5)

- [CWE-471 — Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-602 — Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Prerequisites

- Targeted software is utilizing application framework APIs

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
