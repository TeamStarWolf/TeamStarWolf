# CAPEC-224: Fingerprinting

<a id="capec-224"></a>

Abstraction: Meta  
Typical severity: Very Low  
Likelihood: High  
Status: Stable  

An adversary compares output from a target system to known indicators that uniquely identify specific details about the target. Most commonly, fingerprinting is done to determine operating system and application versions. Fingerprinting can be done passively as well as actively. Fingerprinting by itself is not usually detrimental to the target. However, the information gathered through fingerprinting often enables an adversary to discover existing weaknesses in the target.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- A means by which to interact with the target system directly.

## Skills required

- [Medium] Some fingerprinting activity requires very specific knowledge of how different operating systems respond to various TCP/IP requests. Application fingerprinting can be as easy as envoking the application with the correct command line argument, or mouse clicking in the appropriate place on the screen.

## Consequences

- Confidentiality / Read Data

## Mitigations

- While some information is shared by systems automatically based on standards and protocols, remove potentially sensitive information that is not necessary for the application's functionality as much as possible.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
