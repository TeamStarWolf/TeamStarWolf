# CAPEC-628: Carry-Off GPS Attack

<a id="capec-628"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  
OpenCRE: [CAPEC-628](https://opencre.org/smartlink/standard/CAPEC/628)  

A common form of a GPS spoofing attack, commonly termed a carry-off attack begins with an adversary broadcasting signals synchronized with the genuine signals observed by the target receiver. The power of the counterfeit signals is then gradually increased and drawn away from the genuine signals. Over time, the adversary can carry the target away from their intended destination and toward a location chosen by the adversary.

## Prerequisites

- The target must be relying on valid GPS signal to perform critical operations.

## Skills required

- [High] This attack requires advanced knoweldge in GPS technology.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
