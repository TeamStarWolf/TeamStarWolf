# CAPEC-38 — Leveraging/Manipulating Configuration File Search Paths

<a id="capec-38"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

This pattern of attack sees an adversary load a malicious resource into a program's standard path so that when a known command is executed then the system instead executes the malicious component. The adversary can either modify the search path a program uses, like a PATH variable or classpath, or they can manipulate resources on the path to point to their malicious components. J2EE applications a

## Mapped ATT&CK techniques (2)

- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md)
- [T1574.009 — Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md)

## Related CWE (2)

- [CWE-426 — Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-427 — Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

## Prerequisites

- The attacker must be able to write to redirect search paths on the victim host.

## Skills required

- To identify and execute against an over-privileged system interface:LEVEL:Low

## Mitigations

- Design: Enforce principle of least privilege
- Design: Ensure that the program's compound parts, including all system dependencies, classpath, path, and so on, are secured to the same or higher level assurance as the program
- Implementation: Host in

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
