# CAPEC-38: Leveraging/Manipulating Configuration File Search Paths

<a id="capec-38"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

This pattern of attack sees an adversary load a malicious resource into a program's standard path so that when a known command is executed then the system instead executes the malicious component. The adversary can either modify the search path a program uses, like a PATH variable or classpath, or they can manipulate resources on the path to point to their malicious components. J2EE applications and other component based applications that are built from multiple binaries can have very long list of dependencies to execute. If one of these libraries and/or references is controllable by the attacker then application controls can be circumvented by the attacker.

## Mapped ATT&CK techniques (2)

- [T1574.007: Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md): Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.
- [T1574.009: Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md): Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.

## Related CWE (2)

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html): The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control.
- [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html): The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.

## Prerequisites

- The attacker must be able to write to redirect search paths on the victim host.

## Skills required

- [Low] To identify and execute against an over-privileged system interface

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Design: Enforce principle of least privilege
- Design: Ensure that the program's compound parts, including all system dependencies, classpath, path, and so on, are secured to the same or higher level assurance as the program
- Implementation: Host integrity monitoring

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
