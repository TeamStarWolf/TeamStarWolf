# CAPEC-114 — Authentication Abuse

<a id="capec-114"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

An attacker obtains unauthorized access to an application, service or device either through knowledge of the inherent weaknesses of an authentication mechanism, or by exploiting a flaw in the authentication scheme's implementation. In such an attack an authentication mechanism is functioning but a carefully controlled sequence of events causes the mechanism to grant access to the attacker.

## Mapped ATT&CK techniques (1)

- [T1548 — Abuse Elevation Control Mechanism](/mitre/techniques/T1548.md)

## Related CWE (2)

- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-1244 — Internal Asset Exposed to Unsafe Debug Access Level or State](https://cwe.mitre.org/data/definitions/1244.html)

## Prerequisites

- An authentication mechanism or subsystem implementing some form of authentication such as passwords, digest authentication, security certificates, etc. which is flawed in some way.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
