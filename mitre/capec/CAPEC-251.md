# CAPEC-251: Local Code Inclusion

<a id="capec-251"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Stable  

The attacker forces an application to load arbitrary code files from the local machine. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load files that the attacker placed on the local machine during a prior attack, or to otherwise change the functionality of the targeted application in unexpected ways.

## Mapped ATT&CK techniques (1)

- [T1055: Process Injection](/mitre/techniques/T1055.md): Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted application must have a bug that allows an adversary to control which code file is loaded at some juncture.
- Some variants of this attack may require that old versions of some code files be present and in predictable locations.

## Consequences

- Integrity / Execute Unauthorized Commands
- Confidentiality / Read Data

## Mitigations

- Implementation: Avoid passing user input to filesystem or framework API. If necessary to do so, implement a specific, allowlist approach.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
