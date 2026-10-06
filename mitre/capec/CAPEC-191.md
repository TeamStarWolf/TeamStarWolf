# CAPEC-191: Read Sensitive Constants Within an Executable

<a id="capec-191"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An adversary engages in activities to discover any sensitive constants present within the compiled code of an executable. These constants may include literal ASCII strings within the file itself, or possibly strings hard-coded into particular routines that can be revealed by code refactoring methods including static and dynamic analysis.

## Mapped ATT&CK techniques (1)

- [T1552.001: Credentials In Files](/mitre/techniques/T1552-001.md): Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.

## Related CWE (1)

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html): The product contains hard-coded credentials, such as a password or cryptographic key.

## Prerequisites

- Access to a binary or executable such that it can be analyzed by various utilities.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
