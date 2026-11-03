# CAPEC-618: Cellular Broadcast Message Request

<a id="capec-618"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker uses knowledge of the target’s mobile phone number (i.e., the number associated with the SIM used in the retransmission device) to cause the cellular network to send broadcast messages to alert the mobile device. Since the network knows which cell tower the target’s mobile device is attached to, the broadcast messages are only sent in the Location Area Code (LAC) where the target is currently located. By triggering the cellular broadcast message and then listening for the presence or absence of that message, an attacker could verify that the target is in (or not in) a given location.

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- The attacker must have knowledge of the target’s mobile phone number.

## Skills required

- [Low] Open source and commercial tools are available for this attack.

## Consequences

- Other / Other

## Mitigations

- Frequent changing of mobile number.

## Related pages

- [CAPEC-12: Choosing Message Identifier](/mitre/capec/CAPEC-12.md), also related to CWE-201
- [CAPEC-217: Exploiting Incorrectly Configured SSL/TLS](/mitre/capec/CAPEC-217.md), also related to CWE-201
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-201
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-201
- [CAPEC-619: Signal Strength Tracking](/mitre/capec/CAPEC-619.md), also related to CWE-201
- [CAPEC-621: Analysis of Packet Timing and Sizes](/mitre/capec/CAPEC-621.md), also related to CWE-201
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
