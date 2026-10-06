# CAPEC-558: Replace Trusted Executable

<a id="capec-558"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Stable  

An adversary exploits weaknesses in privilege management or access control to replace a trusted executable with a malicious version and enable the execution of malware when that trusted executable is called.

## Mapped ATT&CK techniques (2)

- [T1505.005: Terminal Services DLL](/mitre/techniques/T1505-005.md): Adversaries may abuse components of Terminal Services to enable persistent access to systems.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
