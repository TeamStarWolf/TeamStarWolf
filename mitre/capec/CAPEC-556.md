# CAPEC-556 — Replace File Extension Handlers

<a id="capec-556"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

When a file is opened, its file handler is checked to determine which program opens the file. File handlers are configuration properties of many operating systems. Applications can modify the file handler for a given file extension to call an arbitrary program when a file with the given extension is opened.

## Mapped ATT&CK techniques (1)

- [T1546.001](/mitre/techniques/T1546-001.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Mitigations:** ::Inspect registry for changes. Limit privileges of user accounts so changes to default file handlers can only be performed by authorized administrators.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
