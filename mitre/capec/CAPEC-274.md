# CAPEC-274 — HTTP Verb Tampering

<a id="capec-274"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker modifies the HTTP Verb (e.g. GET, PUT, TRACE, etc.) in order to bypass access restrictions. Some web environments allow administrators to restrict access based on the HTTP Verb used with requests. However, attackers can often provide a different HTTP Verb, or even provide a random string as a verb in order to bypass these protections. This allows the attacker to access data that should

## Related CWE (2)

- [CWE-302 — Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)

## Prerequisites

- The targeted system must attempt to filter access based on the HTTP verb used in requests.

## Mitigations

- Design: Ensure that only legitimate HTTP verbs are allowed.
- Design: Do not use HTTP verbs as factors in access decisions.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
