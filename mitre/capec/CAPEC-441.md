# CAPEC-441 — Malicious Logic Insertion

<a id="capec-441"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary installs or adds malicious logic (also known as malware) into a seemingly benign component of a fielded system. This logic is often hidden from the user of the system and works behind the scenes to achieve negative impacts. With the proliferation of mass digital storage and inexpensive multimedia devices, Bluetooth and 802.11 support, new attack vectors for spreading malware are emerging for things we once thought of as innocuous greeting cards, picture frames, or digital projectors. This pattern of attack focuses on systems already fielded and used in operation as opposed to systems and their components that are still under development and part of the supply chain.

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- Access to the component currently deployed at a victim location.

## Consequences

- Authorization / Execute Unauthorized Commands

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
