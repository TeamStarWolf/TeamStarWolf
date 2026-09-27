# CAPEC-643 — Identify Shared Files/Directories on System

<a id="capec-643"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An adversary discovers connections between systems by exploiting the target system's standard practice of revealing them in searchable, common areas. Through the identification of shared folders/drives between systems, the adversary may further their goals of locating and collecting sensitive information/files, or map potential routes for lateral movement within the network.

## Mapped ATT&CK techniques (1)

- [T1135 — Network Share Discovery](/mitre/techniques/T1135.md)

## Related CWE (2)

- [CWE-267 — Privilege Defined With Unsafe Actions](https://cwe.mitre.org/data/definitions/267.html)
- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).

## Skills required

- Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only the capability

## Mitigations

- Identify unnecessary system utilities or potentially malicious software that may contain functionality to identify network share information, and audit and/or block them by using allowlist tools.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
