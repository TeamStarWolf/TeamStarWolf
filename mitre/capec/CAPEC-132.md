# CAPEC-132 — Symlink Attack

<a id="capec-132"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary positions a symbolic link in such a manner that the targeted user or application accesses the link's endpoint, assuming that it is accessing a file with the link's name.

## Mapped ATT&CK techniques (1)

- [T1547.009](/mitre/techniques/T1547-009.md)

## Related CWE (1)

[CWE-59](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must perform the desired activities on a file without checking whether the file is a symbolic link or not. The adversary must be able to predict the name of the file the tar

**Skills required:** ::SKILL:To create symlinks:LEVEL:Low::SKILL:To identify the files and create the symlinks during the file operation time window:LEVEL:High::

**Mitigations:** ::Design: Check for the existence of files to be created, if in existence verify they are neither symlinks nor hard links before opening them.::Implementation: Use randomly generated file names for temporary files. Give the files restrictive permissi


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
