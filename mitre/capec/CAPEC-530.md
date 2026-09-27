# CAPEC-530 — Provide Counterfeit Component

<a id="capec-530"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An attacker provides a counterfeit component during the procurement process of a lower-tier component supplier to a sub-system developer or integrator, which is then built into the system being upgraded or repaired by the victim, allowing the attacker to cause disruption or additional compromise.

## Prerequisites

- Advanced knowledge about the target system and sub-components.

## Skills required

- Able to develop and manufacture malicious system components that resemble legitimate name-brand components.:LEVEL:High

## Mitigations

- There are various methods to detect if the component is a counterfeit. See section II of [REF-703] for many techniques.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
