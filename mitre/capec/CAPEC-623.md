# CAPEC-623: Compromising Emanations Attack

<a id="capec-623"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

Compromising Emanations (CE) are defined as unintentional signals which an attacker may intercept and analyze to disclose the information processed by the targeted equipment. Commercial mobile devices and retransmission devices have displays, buttons, microchips, and radios that emit mechanical emissions in the form of sound or vibrations. Capturing these emissions can help an adversary understand what the device is doing.

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- Proximal access to the device.

## Skills required

- [High] Sophisticated attack.

## Consequences

- Confidentiality / Read Data

## Mitigations

- None are known.

## Related pages

- [CAPEC-12: Choosing Message Identifier](/mitre/capec/CAPEC-12.md), also related to CWE-201
- [CAPEC-217: Exploiting Incorrectly Configured SSL/TLS](/mitre/capec/CAPEC-217.md), also related to CWE-201
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-201
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-201
- [CAPEC-618: Cellular Broadcast Message Request](/mitre/capec/CAPEC-618.md), also related to CWE-201
- [CAPEC-619: Signal Strength Tracking](/mitre/capec/CAPEC-619.md), also related to CWE-201
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
