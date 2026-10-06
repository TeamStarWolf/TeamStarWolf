# CAPEC-216: Communication Channel Manipulation

<a id="capec-216"></a>

Abstraction: Meta  
Status: Stable  

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

## Related CWE (1)

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html): The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Prerequisites

- The target application must leverage an open communications channel.
- The channel on which the target communicates must be vulnerable to interception (e.g., adversary in the middle attack - CAPEC-94).

## Consequences

- Integrity / Read Data, Modify Data, Other
- Confidentiality / Read Data

## Mitigations

- Encrypt all sensitive communications using properly-configured cryptography.
- Design the communication system such that it associates proper authentication/authorization with each channel/message.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
