# CAPEC-619: Signal Strength Tracking

<a id="capec-619"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

In this attack scenario, the attacker passively monitors the signal strength of the target’s cellular RF signal or WiFi RF signal and uses the strength of the signal (with directional antennas and/or from multiple listening points at once) to identify the source location of the signal. Obtaining the signal of the target can be accomplished through multiple techniques such as through Cellular Broadcast Message Request or through the use of IMSI Tracking or WiFi MAC Address Tracking.

## Related CWE (1)

- [CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html): The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

## Skills required

- [Low] Commercial tools are available.

## Related pages

- [CAPEC-12: Choosing Message Identifier](/mitre/capec/CAPEC-12.md), also related to CWE-201
- [CAPEC-217: Exploiting Incorrectly Configured SSL/TLS](/mitre/capec/CAPEC-217.md), also related to CWE-201
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-201
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-201
- [CAPEC-618: Cellular Broadcast Message Request](/mitre/capec/CAPEC-618.md), also related to CWE-201
- [CAPEC-621: Analysis of Packet Timing and Sizes](/mitre/capec/CAPEC-621.md), also related to CWE-201
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
