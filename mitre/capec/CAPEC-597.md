# CAPEC-597 — Absolute Path Traversal

<a id="capec-597"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary with access to file system resources, either directly or via application logic, will use various file absolute paths and navigation mechanisms such as .. to extend their range of access to inappropriate areas of the file system. The goal of the adversary is to access directories and files that are intended to be restricted from their access.

## Related CWE (1)

- [CWE-36 — Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html) — The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as /abs/path that can resolve to a location that is…

## Prerequisites

- The target must leverage and access an underlying file system.

## Skills required

- Simple command line attacks.:LEVEL:Low
- Programming attacks.:LEVEL:Medium

## Mitigations

- Design: Configure the access control correctly.
- Design: Enforce principle of least privilege.
- Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
