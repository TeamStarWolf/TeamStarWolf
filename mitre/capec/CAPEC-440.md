# CAPEC-440: Hardware Integrity Attack

<a id="capec-440"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: Low  
Status: Stable  
OpenCRE: [CAPEC-440](https://opencre.org/smartlink/standard/CAPEC/440)  

An adversary exploits a weakness in the system maintenance process and causes a change to be made to a technology, product, component, or sub-component or a new one installed during its deployed use at the victim location for the purpose of carrying out an attack.

## Mapped ATT&CK techniques (2)

- [T1195.003: Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md): Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.
- [T1200: Hardware Additions](/mitre/techniques/T1200.md): Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access.

## Prerequisites

- Influence over the deployed system at a victim location.

## Consequences

- Integrity / Execute Unauthorized Commands

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
