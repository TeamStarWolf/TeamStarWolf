# CAPEC-132 — Symlink Attack

<a id="capec-132"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary positions a symbolic link in such a manner that the targeted user or application accesses the link's endpoint, assuming that it is accessing a file with the link's name.

## Mapped ATT&CK techniques (1)

- [T1547.009 — Shortcut Modification](/mitre/techniques/T1547-009.md) — Adversaries may create or modify shortcuts that can execute a program during system boot or user login.

## Related CWE (1)

- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html) — The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Prerequisites

- The targeted application must perform the desired activities on a file without checking whether the file is a symbolic link or not. The adversary must be able to predict the name of the file the target application is modifying and be able to create a new symbolic link where that file would appear.

## Skills required

- [Low] To create symlinks
- [High] To identify the files and create the symlinks during the file operation time window

## Consequences

- Confidentiality / Other
- Integrity / Modify Data
- Confidentiality / Read Data
- Integrity / Modify Data
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges
- Access Control, Authorization / Bypass Protection Mechanism
- Availability / Unreliable Execution

## Mitigations

- Design: Check for the existence of files to be created, if in existence verify they are neither symlinks nor hard links before opening them.
- Implementation: Use randomly generated file names for temporary files. Give the files restrictive permissions.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
