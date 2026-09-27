# CAPEC-649 — Adding a Space to a File Extension

<a id="capec-649"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low

An adversary adds a space character to the end of a file extension and takes advantage of an application that does not properly neutralize trailing special elements in file names. This extra space, which can be difficult for a user to notice, affects which default application is used to operate on the file and can be leveraged by the adversary to control execution.

## Mapped ATT&CK techniques (1)

- [T1036.006](/mitre/techniques/T1036-006.md)

## Related CWE (1)

[CWE-46](/CWE_REFERENCE.md)

**Prerequisites:** ::The use of the file must be controlled by the file extension.::

**Mitigations:** ::File extensions should be checked to see if non-visible characters are being included.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
