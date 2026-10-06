# CAPEC-157: Sniffing Attacks

<a id="capec-157"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient. Sniffing Attacks are similar to Adversary-In-The-Middle attacks (CAPEC-94), but are entirely passive. AiTM attacks are predominantly active and often alter the content of the communications themselves.

## Related CWE (1)

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- The target data stream must be transmitted on a medium to which the adversary has access.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
