# CAPEC-597 — Absolute Path Traversal

<a id="capec-597"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

An adversary with access to file system resources, either directly or via application logic, will use various file absolute paths and navigation mechanisms such as .. to extend their range of access to inappropriate areas of the file system. The goal of the adversary is to access directories and files that are intended to be restricted from their access.

## Related CWE (1)

[CWE-36](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must leverage and access an underlying file system.::

**Skills required:** ::SKILL:Simple command line attacks.:LEVEL:Low::SKILL:Programming attacks.:LEVEL:Medium::

**Mitigations:** ::Design: Configure the access control correctly.::Design: Enforce principle of least privilege.::Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
