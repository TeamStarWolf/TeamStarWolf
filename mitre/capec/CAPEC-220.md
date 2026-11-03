# CAPEC-220: Client-Server Protocol Manipulation

<a id="capec-220"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions.

## Related CWE (1)

- [CWE-757: Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html): A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used in a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

## Prerequisites

- The client and/or server must utilize a protocol that has a weakness allowing manipulation of the interaction.

## Related pages

- [CAPEC-606: Weakening of Cellular Encryption](/mitre/capec/CAPEC-606.md), also related to CWE-757
- [CAPEC-620: Drop Encryption Level](/mitre/capec/CAPEC-620.md), also related to CWE-757
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
