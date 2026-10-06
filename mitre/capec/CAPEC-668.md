# CAPEC-668: Key Negotiation of Bluetooth Attack (KNOB)

<a id="capec-668"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary can exploit a flaw in Bluetooth key negotiation allowing them to decrypt information sent between two devices communicating via Bluetooth. The adversary uses an Adversary in the Middle setup to modify packets sent between the two devices during the authentication process, specifically the entropy bits. Knowledge of the number of entropy bits will allow the attacker to easily decrypt information passing over the line of communication.

## Mapped ATT&CK techniques (1)

- [T1565.002: Transmitted Data Manipulation](/mitre/techniques/T1565-002.md): Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data.

## Related CWE (3)

- [CWE-425: Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html): The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- Person in the Middle network setup.

## Skills required

- [Medium] Ability to modify packets.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism
- Integrity / Modify Data

## Mitigations

- Newer Bluetooth firmwares ensure that the KNOB is not negotaited in plaintext. Update your device.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
