# CAPEC-621: Analysis of Packet Timing and Sizes

<a id="capec-621"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An attacker may intercept and log encrypted transmissions for the purpose of analyzing metadata such as packet timing and sizes. Although the actual data may be encrypted, this metadata may reveal valuable information to an attacker. Note that this attack is applicable to VOIP data as well as application data, especially for interactive apps that require precise timing and low-latency (e.g. thin-clients).

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Prerequisites

- Use of untrusted communication paths enables an attacker to intercept and log communications, including metadata such as packet timing and sizes.

## Skills required

- [High] These attacks generally require sophisticated machine learning techniques and require traffic capture as a prerequisite.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Distort packet sizes and timing at VPN layer by adding padding to normalize packet sizes and timing delays to reduce information leakage via timing.

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
