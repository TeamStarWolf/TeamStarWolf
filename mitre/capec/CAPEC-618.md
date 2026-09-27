# CAPEC-618 — Cellular Broadcast Message Request

<a id="capec-618"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

In this attack scenario, the attacker uses knowledge of the target’s mobile phone number (i.e., the number associated with the SIM used in the retransmission device) to cause the cellular network to send broadcast messages to alert the mobile device. Since the network knows which cell tower the target’s mobile device is attached to, the broadcast messages are only sent in the Location Area Code (L

## Related CWE (1)

- [CWE-201 — Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html) — The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- The attacker must have knowledge of the target’s mobile phone number.

## Skills required

- Open source and commercial tools are available for this attack.:LEVEL:Low

## Mitigations

- Frequent changing of mobile number.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
