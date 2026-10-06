# CAPEC-220: Client-Server Protocol Manipulation

<a id="capec-220"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions.

## Related CWE (1)

- [CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html): A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

## Prerequisites

- The client and/or server must utilize a protocol that has a weakness allowing manipulation of the interaction.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
