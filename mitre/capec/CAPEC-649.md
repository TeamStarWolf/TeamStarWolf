# CAPEC-649 — Adding a Space to a File Extension

<a id="capec-649"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Draft  

An adversary adds a space character to the end of a file extension and takes advantage of an application that does not properly neutralize trailing special elements in file names. This extra space, which can be difficult for a user to notice, affects which default application is used to operate on the file and can be leveraged by the adversary to control execution.

## Mapped ATT&CK techniques (1)

- [T1036.006 — Space after Filename](/mitre/techniques/T1036-006.md) — Adversaries can hide a program's true filetype by changing the extension of a file.

## Related CWE (1)

- [CWE-46 — Path Equivalence: 'filename ' (Trailing Space)](https://cwe.mitre.org/data/definitions/46.html) — The product accepts path input in the form of trailing space ('filedir ') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Prerequisites

- The use of the file must be controlled by the file extension.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- File extensions should be checked to see if non-visible characters are being included.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
