# CAPEC-669: Alteration of a Software Update

<a id="capec-669"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary with access to an organization’s software update infrastructure inserts malware into the content of an outgoing update to fielded systems where a wide range of malicious effects are possible. With the same level of access, the adversary can alter a software update to perform specific malicious acts including granting the adversary control over the software’s normal functionality.

## Mapped ATT&CK techniques (1)

- [T1195.002: Compromise Software Supply Chain](/mitre/techniques/T1195-002.md): Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- An adversary would need to have penetrated an organization’s software update infrastructure including gaining access to components supporting the configuration management of software versions and updates related to the software maintenance of customer systems.

## Skills required

- [High] Skills required include the ability to infiltrate the organization’s software update infrastructure either from the Internet or from within the organization, including subcontractors, and be able to change software being delivered to customer/user systems in an undetected manner.

## Consequences

- Access Control / Gain Privileges
- Authorization / Execute Unauthorized Commands
- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Have a Software Assurance Plan that includes maintaining strict configuration management control of source code, object code and software development, build and distribution tools; manual code reviews and static code analysis for developmental software; and tracking of all storage and movement of code.
- Require elevated privileges for distribution of software and software updates.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
