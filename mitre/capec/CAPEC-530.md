# CAPEC-530: Provide Counterfeit Component

<a id="capec-530"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  
OpenCRE: [CAPEC-530](https://opencre.org/smartlink/standard/CAPEC/530)  

An attacker provides a counterfeit component during the procurement process of a lower-tier component supplier to a sub-system developer or integrator, which is then built into the system being upgraded or repaired by the victim, allowing the attacker to cause disruption or additional compromise.

## Prerequisites

- Advanced knowledge about the target system and sub-components.

## Skills required

- [High] Able to develop and manufacture malicious system components that resemble legitimate name-brand components.

## Mitigations

- There are various methods to detect if the component is a counterfeit. See section II of [REF-703] for many techniques.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
