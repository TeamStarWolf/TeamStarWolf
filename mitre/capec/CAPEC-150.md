# CAPEC-150 — Collect Data from Common Resource Locations

<a id="capec-150"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An adversary exploits well-known locations for resources for the purposes of undermining the security of the target. In many, if not most systems, files and resources are organized in a default tree structure. This can be useful for adversaries because they often know where to look for resources or files that are necessary for attacks. Even when the precise location of a targeted resource may not

## Mapped ATT&CK techniques (6)

- [T1003 — OS Credential Dumping](/mitre/techniques/T1003.md)
- [T1119 — Automated Collection](/mitre/techniques/T1119.md)
- [T1213 — Data from Information Repositories](/mitre/techniques/T1213.md)
- [T1530 — Data from Cloud Storage](/mitre/techniques/T1530.md)
- [T1555 — Credentials from Password Stores](/mitre/techniques/T1555.md)
- [T1602 — Data from Configuration Repository](/mitre/techniques/T1602.md)

## Related CWE (7)

- [CWE-552 — Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [CWE-1239 — Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html)
- [CWE-1258 — Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html)
- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html)
- [CWE-1272 — Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html)
- [CWE-1323 — Improper Management of Sensitive Trace Data](https://cwe.mitre.org/data/definitions/1323.html)
- [CWE-1330 — Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html)

## Prerequisites

- The targeted applications must either expect files to be located at a specific location or, if the location of the files can be configured by the user, the user either failed to move the files from

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
