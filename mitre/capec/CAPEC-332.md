# CAPEC-332: ICMP IP 'ID' Field Error Message Probe

<a id="capec-332"></a>

Abstraction: Detailed  
Typical severity: Low  
Likelihood: Medium  
Status: Stable  

An adversary sends a UDP datagram having an assigned value to its internet identification field (ID) to a closed port on a target to observe the manner in which this bit is echoed back in the ICMP error message. This allows the attacker to construct a fingerprint of specific OS behaviors.

## Related CWE (1)

- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html): The product provides different responses to incoming requests in a way that reveals internal state information to an unauthorized actor outside of the intended control sphere.

## Prerequisites

- The ability to monitor and interact with network communications. Access to at least one host, and the privileges to interface with the network interface card.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

## Related pages

- [CAPEC-331: ICMP IP Total Length Field Probe](/mitre/capec/CAPEC-331.md), also related to CWE-204
- [CAPEC-541: Application Fingerprinting](/mitre/capec/CAPEC-541.md), also related to CWE-204
- [CAPEC-580: System Footprinting](/mitre/capec/CAPEC-580.md), also related to CWE-204
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
