# CAPEC-531: Hardware Component Substitution

<a id="capec-531"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  
OpenCRE: [CAPEC-531](https://opencre.org/smartlink/standard/CAPEC/531)  

An attacker substitutes out a tested and approved hardware component for a maliciously-altered hardware component. This type of attack is carried out directly on the system, enabling the attacker to then cause disruption or additional compromise.

## Mapped ATT&CK techniques (1)

- [T1195.003: Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md): Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- Physical access to the system or the integration facility where hardware components are kept.

## Skills required

- [High] Able to develop and manufacture malicious system components that perform the same functions and processes as their non-malicious counterparts.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
