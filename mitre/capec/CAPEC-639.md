# CAPEC-639 — Probe System Files

<a id="capec-639"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary obtains unauthorized information due to improperly protected files. If an application stores sensitive information in a file that is not protected by proper access control, then an adversary can access the file and search for sensitive information.

## Mapped ATT&CK techniques (5)

- [T1039](/mitre/techniques/T1039.md)
- [T1552.001](/mitre/techniques/T1552-001.md)
- [T1552.003](/mitre/techniques/T1552-003.md)
- [T1552.004](/mitre/techniques/T1552-004.md)
- [T1552.006](/mitre/techniques/T1552-006.md)

## Related CWE (1)

[CWE-552](/CWE_REFERENCE.md)

**Prerequisites:** ::An adversary has access to the file system of a system.::

**Mitigations:** ::Verify that files have proper access controls set, and reduce the storage of sensitive information to only what is necessary.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
