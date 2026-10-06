# CAPEC-694: System Location Discovery

<a id="capec-694"></a>

Abstraction: Standard  
Typical severity: Very Low  
Likelihood: High  
Status: Stable  

An adversary collects information about the target system in an attempt to identify the system's geographical location. Information gathered could include keyboard layout, system language, and timezone. This information may benefit an adversary in confirming the desired target and/or tailoring further attacks.

## Mapped ATT&CK techniques (1)

- [T1614: System Location Discovery](/mitre/techniques/T1614.md): Adversaries may gather information in an attempt to calculate the geographical location of a victim host.

## Related CWE (1)

- [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html): The product does not properly prevent sensitive system-level information from being accessed by unauthorized actors who do not have the same level of access to the underlying system as the product does.

## Prerequisites

- The adversary must have some level of access to the system and have a basic understanding of the operating system in order to query the appropriate sources for relevant information.

## Skills required

- [Low] The adversary must know how to query various system sources of information respective of the system's operating system to obtain the relevant information.

## Consequences

- Confidentiality / Read Data

## Mitigations

- To reduce the amount of information gathered, one could disable various geolocation features of the operating system not required for system operation.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
