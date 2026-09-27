# CAPEC-113 — Interface Manipulation

<a id="capec-113"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An adversary manipulates the use or processing of an interface (e.g. Application Programming Interface (API) or System-on-Chip (SoC)) resulting in an adverse impact upon the security of the system implementing the interface. This can allow the adversary to bypass access control and/or execute functionality not intended by the interface implementation, possibly compromising the system which integra

## Related CWE (1)

- [CWE-1192 — Improper Identifier for IP Block used in System-On-Chip (SOC)](https://cwe.mitre.org/data/definitions/1192.html)

## Prerequisites

- The target system must expose interface functionality in a manner that can be discovered and manipulated by an adversary. This may require reverse engineering the interface or decrypting/de-obfuscat

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
