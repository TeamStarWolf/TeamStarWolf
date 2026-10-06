# CAPEC-622: Electromagnetic Side-Channel Attack

<a id="capec-622"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker passively monitors electromagnetic emanations that are produced by the targeted electronic device as an unintentional side-effect of its processing. From these emanations, the attacker derives information about the data that is being processed (e.g. the attacker can recover cryptographic keys by monitoring emanations associated with cryptographic processing). This style of attack requires proximal access to the device, however attacks have been demonstrated at public conferences that work at distances of up to 10-15 feet. There have not been any significant studies to determine the maximum practical distance for such attacks. Since the attack is passive, it is nearly impossible to detect and the targeted device will continue to operate as normal after a successful attack.

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- Proximal access to the device.

## Skills required

- [Medium] Sophisticated attack, but detailed techniques published in the open literature.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Utilize side-channel resistant implementations of all crypto algorithms.
- Strong physical security of all devices that contain secret key information. (even when devices are not in use)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
