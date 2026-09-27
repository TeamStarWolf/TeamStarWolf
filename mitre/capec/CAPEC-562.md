# CAPEC-562 — Modify Shared File

<a id="capec-562"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary manipulates the files in a shared location by adding malicious programs, scripts, or exploit code to valid content. Once a user opens the shared content, the tainted content is executed.

## Mapped ATT&CK techniques (1)

- [T1080](/mitre/techniques/T1080.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Mitigations:** ::Disallow shared content. Protect shared folders by minimizing users that have write access. Use utilities that mitigate exploitation like the Microsoft Enhanced Mitigation Experience Toolkit (EMET) to prevent exploits from being run.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
