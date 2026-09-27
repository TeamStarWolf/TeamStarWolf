# CAPEC-623 — Compromising Emanations Attack

<a id="capec-623"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

Compromising Emanations (CE) are defined as unintentional signals which an attacker may intercept and analyze to disclose the information processed by the targeted equipment. Commercial mobile devices and retransmission devices have displays, buttons, microchips, and radios that emit mechanical emissions in the form of sound or vibrations. Capturing these emissions can help an adversary understand what the device is doing.

## Related CWE (1)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html) — The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- Proximal access to the device.

## Skills required

- [High] Sophisticated attack.

## Consequences

- Confidentiality / Read Data

## Mitigations

- None are known.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
