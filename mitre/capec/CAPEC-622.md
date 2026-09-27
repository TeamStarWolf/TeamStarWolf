# CAPEC-622 — Electromagnetic Side-Channel Attack

<a id="capec-622"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

In this attack scenario, the attacker passively monitors electromagnetic emanations that are produced by the targeted electronic device as an unintentional side-effect of its processing. From these emanations, the attacker derives information about the data that is being processed (e.g. the attacker can recover cryptographic keys by monitoring emanations associated with cryptographic processing).

## Related CWE (1)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)

## Prerequisites

- Proximal access to the device.

## Skills required

- Sophisticated attack, but detailed techniques published in the open literature.:LEVEL:Medium

## Mitigations

- Utilize side-channel resistant implementations of all crypto algorithms.
- Strong physical security of all devices that contain secret key information. (even when devices are not in use)

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
