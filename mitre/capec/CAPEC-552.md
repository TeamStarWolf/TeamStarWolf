# CAPEC-552: Install Rootkit

<a id="capec-552"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary exploits a weakness in authentication to install malware that alters the functionality and information provide by targeted operating system API calls. Often referred to as rootkits, it is often used to hide the presence of programs, files, network connections, services, drivers, and other system components.

## Mapped ATT&CK techniques (3)

- [T1014: Rootkit](/mitre/techniques/T1014.md): Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.
- [T1542.003: Bootkit](/mitre/techniques/T1542-003.md): Adversaries may use bootkits to persist on systems.
- [T1547.006: Kernel Modules and Extensions](/mitre/techniques/T1547-006.md): Adversaries may modify the kernel to automatically execute programs on system boot.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Prevent adversary access to privileged accounts necessary to install rootkits.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
