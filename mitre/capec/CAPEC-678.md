# CAPEC-678: System Build Data Maliciously Altered

<a id="capec-678"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

During the system build process, the system is deliberately misconfigured by the alteration of the build data. Access to system configuration data files and build processes is susceptible to deliberate misconfiguration of the system.

## Mapped ATT&CK techniques (1)

- [T1195.002: Compromise Software Supply Chain](/mitre/techniques/T1195-002.md): Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- An adversary has access to the data files and processes used for executing system configuration and performing the build.

## Consequences

- Integrity / Execute Unauthorized Commands
- Access Control / Gain Privileges
- Confidentiality / Modify Data, Read Data

## Mitigations

- Implement configuration management security practices that protect the integrity of software and associated data.
- Monitor and control access to the configuration management system.
- Harden centralized repositories against attack.
- Establish acceptance criteria for configuration management check-in to assure integrity.
- Plan for and audit the security of configuration management administration processes.
- Maintain configuration control over operational systems.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
