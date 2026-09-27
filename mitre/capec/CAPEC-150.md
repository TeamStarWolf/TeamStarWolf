# CAPEC-150 — Collect Data from Common Resource Locations

<a id="capec-150"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

An adversary exploits well-known locations for resources for the purposes of undermining the security of the target. In many, if not most systems, files and resources are organized in a default tree structure. This can be useful for adversaries because they often know where to look for resources or files that are necessary for attacks. Even when the precise location of a targeted resource may not

## Mapped ATT&CK techniques (6)

- [T1003](/mitre/techniques/T1003.md)
- [T1119](/mitre/techniques/T1119.md)
- [T1213](/mitre/techniques/T1213.md)
- [T1530](/mitre/techniques/T1530.md)
- [T1555](/mitre/techniques/T1555.md)
- [T1602](/mitre/techniques/T1602.md)

## Related CWE (7)

[CWE-552](/CWE_REFERENCE.md) [CWE-1239](/CWE_REFERENCE.md) [CWE-1258](/CWE_REFERENCE.md) [CWE-1266](/CWE_REFERENCE.md) [CWE-1272](/CWE_REFERENCE.md) [CWE-1323](/CWE_REFERENCE.md) [CWE-1330](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted applications must either expect files to be located at a specific location or, if the location of the files can be configured by the user, the user either failed to move the files from 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
