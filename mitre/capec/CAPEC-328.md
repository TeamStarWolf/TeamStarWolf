# CAPEC-328: TCP 'RST' Flag Checksum Probe

<a id="capec-328"></a>

Abstraction: Detailed  
Typical severity: Low  
Likelihood: Medium  
Status: Stable  

This OS fingerprinting probe performs a checksum on any ASCII data contained within the data portion or a RST packet. Some operating systems will report a human-readable text message in the payload of a 'RST' (reset) packet when specific types of connection errors occur. RFC 1122 allows text payloads within reset packets but not all operating systems or routers implement this functionality.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
