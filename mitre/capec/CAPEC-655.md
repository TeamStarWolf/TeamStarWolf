# CAPEC-655: Avoid Security Tool Identification by Adding Data

<a id="capec-655"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An adversary adds data to a file to increase the file size beyond what security tools are capable of handling in an attempt to mask their actions. In addition to this, adding data to a file also changes the file's hash, frustrating security tools that look for known bad files by their hash.

## Mapped ATT&CK techniques (1)

- [T1027.001: Binary Padding](/mitre/techniques/T1027-001.md): Adversaries may use binary padding to add junk data and change the on-disk representation of malware.

## Consequences

- Accountability / Hide Activities, Bypass Protection Mechanism
- Integrity / Modify Data

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
