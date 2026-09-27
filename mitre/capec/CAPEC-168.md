# CAPEC-168 — Windows ::DATA Alternate Data Stream

<a id="capec-168"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An attacker exploits the functionality of Microsoft NTFS Alternate Data Streams (ADS) to undermine system security. ADS allows multiple files to be stored in one directory entry referenced as filename:streamname. One or more alternate data streams may be stored in any file or directory. Normal Microsoft utilities do not show the presence of an ADS stream attached to a file. The additional space fo

## Related CWE (2)

[CWE-212](/CWE_REFERENCE.md) [CWE-69](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must be running the Microsoft NTFS file system.::

**Mitigations:** ::Design: Use FAT file systems which do not support Alternate Data Streams.::Implementation: Use Vista dir with the -R switch or utility to find Alternate Data Streams and take appropriate action with those discovered.::Implementation: Use products t


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
