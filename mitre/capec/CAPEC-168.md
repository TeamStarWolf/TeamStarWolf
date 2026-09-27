# CAPEC-168 — Windows ::DATA Alternate Data Stream

<a id="capec-168"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

An attacker exploits the functionality of Microsoft NTFS Alternate Data Streams (ADS) to undermine system security. ADS allows multiple "files" to be stored in one directory entry referenced as filename:streamname. One or more alternate data streams may be stored in any file or directory. Normal Microsoft utilities do not show the presence of an ADS stream attached to a file. The additional space for the ADS is not recorded in the displayed file size. The additional space for ADS is accounted for in the used space on the volume. An ADS can be any type of file. ADS are copied by standard Microsoft utilities between NTFS volumes. ADS can be used by an attacker or intruder to hide tools, scripts, and data from detection by normal system utilities. Many anti-virus programs do not check for or scan ADS. Windows Vista does have a switch (-R) on the command line DIR command that will display alternate streams.

## Related CWE (2)

- [CWE-212 — Improper Removal of Sensitive Information Before Storage or Transfer](https://cwe.mitre.org/data/definitions/212.html) — The product stores, transfers, or shares a resource that contains sensitive information, but it does not properly remove that information before the product makes the resource available to unauthorized actors.
- [CWE-69 — Improper Handling of Windows ::DATA Alternate Data Stream](https://cwe.mitre.org/data/definitions/69.html) — The product does not properly prevent access to, or detect usage of, alternate data streams (ADS).

## Prerequisites

- The target must be running the Microsoft NTFS file system.

## Mitigations

- Design: Use FAT file systems which do not support Alternate Data Streams.
- Implementation: Use Vista dir with the -R switch or utility to find Alternate Data Streams and take appropriate action with those discovered.
- Implementation: Use products that are Alternate Data Stream aware for virus scanning and system security operations.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
