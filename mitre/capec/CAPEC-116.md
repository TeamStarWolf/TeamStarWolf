# CAPEC-116 — Excavation

<a id="capec-116"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Stable  

An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes.

## Related CWE (2)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-1243 — Sensitive Non-Volatile Information Not Protected During Debug](https://cwe.mitre.org/data/definitions/1243.html) — Access to security-sensitive information stored in fuses is not limited during debug.

## Prerequisites

- An adversary requires some way of interacting with the system.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Minimize error/response output to only what is necessary for functional use or corrective language.
- Remove potentially sensitive information that is not necessary for the application's functionality.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
