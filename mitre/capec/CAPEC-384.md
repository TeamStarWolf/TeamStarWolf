# CAPEC-384: Application API Message Manipulation via Man-in-the-Middle

<a id="capec-384"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An attacker manipulates either egress or ingress data from a client within an application framework in order to change the content of messages. Performing this attack can allow the attacker to gain unauthorized privileges within the application, or conduct attacks such as phishing, deceptive strategies to spread malware, or traditional web-application attacks. The techniques require use of specialized software that allow the attacker to perform adversary-in-the-middle (CAPEC-94) communications between the web browser and the remote system. Despite the use of AiTH software, the attack is actually directed at the server, as the client is one node in a series of content brokers that pass information along to the application framework. Additionally, it is not true "Adversary-in-the-Middle" attack at the network layer, but an application-layer attack the root cause of which is the master applications trust in the integrity of code supplied by the client.

## Related CWE (5)

- [CWE-471: Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html): The product does not properly protect an assumed-immutable element from being modified by an attacker.
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html): The product includes a server that relies on the client to implement a protection mechanism that is intended to protect the server.
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- Targeted software is utilizing application framework APIs

## Related pages

- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), named in the description above
- [CAPEC-385: Transaction or Event Tampering via Application API Manipulation](/mitre/capec/CAPEC-385.md), also related to CWE-311, CWE-345 and 3 more
- [CAPEC-386: Application API Navigation Remapping](/mitre/capec/CAPEC-386.md), also related to CWE-311, CWE-345 and 3 more
- [CAPEC-387: Navigation Remapping To Propagate Malicious Content](/mitre/capec/CAPEC-387.md), also related to CWE-311, CWE-345 and 3 more
- [CAPEC-388: Application API Button Hijacking](/mitre/capec/CAPEC-388.md), also related to CWE-311, CWE-345 and 3 more
- [CAPEC-21: Exploitation of Trusted Identifiers](/mitre/capec/CAPEC-21.md), also related to CWE-346 and CWE-602
- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-311 and CWE-602
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
