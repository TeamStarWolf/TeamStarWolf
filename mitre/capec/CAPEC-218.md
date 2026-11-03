# CAPEC-218: Spoofing of UDDI/ebXML Messages

<a id="capec-218"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An attacker spoofs a UDDI, ebXML, or similar message in order to impersonate a service provider in an e-business transaction. UDDI, ebXML, and similar standards are used to identify businesses in e-business transactions. Among other things, they identify a particular participant, WSDL information for SOAP transactions, and supported communication protocols, including security protocols. By spoofing one of these messages an attacker could impersonate a legitimate business in a transaction or could manipulate the protocols used between a client and business. This could result in disclosure of sensitive information, loss of message integrity, or even financial fraud.

## Related CWE (1)

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Prerequisites

- The targeted business's UDDI or ebXML information must be served from a location that the attacker can spoof or compromise or the attacker must be able to intercept and modify unsecured UDDI/ebXML messages in transit.

## Mitigations

- Implementation: Clients should only trust UDDI, ebXML, or similar messages that are verifiably signed by a trusted party.

## Related pages

- [CAPEC-111: JSON Hijacking (aka JavaScript Hijacking)](/mitre/capec/CAPEC-111.md), also related to CWE-345
- [CAPEC-141: Cache Poisoning](/mitre/capec/CAPEC-141.md), also related to CWE-345
- [CAPEC-142: DNS Cache Poisoning](/mitre/capec/CAPEC-142.md), also related to CWE-345
- [CAPEC-148: Content Spoofing](/mitre/capec/CAPEC-148.md), also related to CWE-345
- [CAPEC-384: Application API Message Manipulation via Man-in-the-Middle](/mitre/capec/CAPEC-384.md), also related to CWE-345
- [CAPEC-385: Transaction or Event Tampering via Application API Manipulation](/mitre/capec/CAPEC-385.md), also related to CWE-345
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
