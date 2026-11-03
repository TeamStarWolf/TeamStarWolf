# CAPEC-389: Content Spoofing Via Application API Manipulation

<a id="capec-389"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An attacker manipulates either egress or ingress data from a client within an application framework in order to change the content of messages. Performing this attack allows the attacker to manipulate content in such a way as to produce messages or content that look authentic but may contain deceptive links, spam-like content, or links to the attackers' code. In general, content-spoofing within an application API can be employed to stage many different types of attacks varied based on the attackers' intent. The techniques require use of specialized software that allow the attacker to use adversary-in-the-middle (CAPEC-94) communications between the web browser and the remote system.

## Related CWE (1)

- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html): The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.

## Prerequisites

- Targeted software is utilizing application framework APIs

## Related pages

- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), named in the description above
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-353
- [CAPEC-14: Client-side Injection-induced Buffer Overflow](/mitre/capec/CAPEC-14.md), also related to CWE-353
- [CAPEC-39: Manipulating Opaque Client-based Data Tokens](/mitre/capec/CAPEC-39.md), also related to CWE-353
- [CAPEC-74: Manipulating State](/mitre/capec/CAPEC-74.md), also related to CWE-353
- [CAPEC-75: Manipulating Writeable Configuration Files](/mitre/capec/CAPEC-75.md), also related to CWE-353
- [CAPEC-665: Exploitation of Thunderbolt Protection Flaws](/mitre/capec/CAPEC-665.md), also related to CWE-353
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
