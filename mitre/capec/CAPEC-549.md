# CAPEC-549: Local Execution of Code

<a id="capec-549"></a>

Abstraction: Meta  
Typical severity: High  
Likelihood: Medium  
Status: Stable  

An adversary installs and executes malicious code on the target system in an effort to achieve a negative technical impact. Examples include rootkits, ransomware, spyware, adware, and others.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- Knowledge of the target system's vulnerabilities that can be capitalized on with malicious code.The adversary must be able to place the malicious code on the target system.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Integrity, Availability / Other

## Mitigations

- Employ robust cybersecurity training for all employees.
- Implement system antivirus software that scans all attachments before opening them.
- Regularly patch all software.
- Execute all suspicious files in a sandbox environment.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
