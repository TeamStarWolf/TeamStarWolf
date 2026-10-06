# CAPEC-646: Peripheral Footprinting

<a id="capec-646"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: Low  
Status: Stable  

Adversaries may attempt to obtain information about attached peripheral devices and components connected to a computer system. Examples may include discovering the presence of iOS devices by searching for backups, analyzing the Windows registry to determine what USB devices have been connected, or infecting a victim system with malware to report when a USB device has been connected. This may allow the adversary to gain additional insight about the system or network environment, which may be useful in constructing further attacks.

## Mapped ATT&CK techniques (1)

- [T1120: Peripheral Device Discovery](/mitre/techniques/T1120.md): Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary needs either physical or remote access to the victim system.

## Skills required

- [Medium] The adversary needs to be able to infect the victim system in a manner that gives them remote access.
- [Medium] If analyzing the Windows registry, the adversary must understand the registry structure to know where to look for devices.

## Mitigations

- Identify programs that may be used to acquire peripheral information and block them by using a software restriction policy or tools that restrict program execution by using a process allowlist.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
