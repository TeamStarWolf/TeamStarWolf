# CAPEC-487: ICMP Flood

<a id="capec-487"></a>

Abstraction: Standard  
Status: Draft  

An adversary may execute a flooding attack using the ICMP protocol with the intent to deny legitimate users access to a service by consuming the available network bandwidth. A typical attack involves a victim server receiving ICMP packets at a high rate from a wide range of source addresses. Additionally, due to the session-less nature of the ICMP protocol, the source of a packet is easily spoofed making it difficult to find the source of the attack.

## Related CWE (1)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- This type of an attack requires the ability to generate a large amount of ICMP traffic to send to the target server.

## Mitigations

- To mitigate this type of an attack, an organization can enable ingress filtering. Additionally modifications to BGP like black hole routing and sinkhole routing(RFC3882) help mitigate the spoofed source IP nature of these attacks.

## Related pages

- [CAPEC-125: Flooding](/mitre/capec/CAPEC-125.md), also related to CWE-770
- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-770
- [CAPEC-147: XML Ping of the Death](/mitre/capec/CAPEC-147.md), also related to CWE-770
- [CAPEC-197: Exponential Data Expansion](/mitre/capec/CAPEC-197.md), also related to CWE-770
- [CAPEC-229: Serialized Data Parameter Blowup](/mitre/capec/CAPEC-229.md), also related to CWE-770
- [CAPEC-230: Serialized Data with Nested Payloads](/mitre/capec/CAPEC-230.md), also related to CWE-770
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
