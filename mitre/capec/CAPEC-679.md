# CAPEC-679 — Exploitation of Improperly Configured or Implemented Memory Protections

<a id="capec-679"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary takes advantage of missing or incorrectly configured access control within memory to read/write data or inject malicious code into said memory.

## Related CWE (9)

- [CWE-1222 — Insufficient Granularity of Address Regions Protected by Register Locks](https://cwe.mitre.org/data/definitions/1222.html)
- [CWE-1252 — CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations](https://cwe.mitre.org/data/definitions/1252.html)
- [CWE-1257 — Improper Access Control Applied to Mirrored or Aliased Memory Regions](https://cwe.mitre.org/data/definitions/1257.html)
- [CWE-1260 — Improper Handling of Overlap Between Protected Memory Ranges](https://cwe.mitre.org/data/definitions/1260.html)
- [CWE-1274 — Improper Access Control for Volatile Memory Containing Boot Code](https://cwe.mitre.org/data/definitions/1274.html)
- [CWE-1282 — Assumed-Immutable Data is Stored in Writable Memory](https://cwe.mitre.org/data/definitions/1282.html)
- [CWE-1312 — Missing Protection for Mirrored Regions in On-Chip Fabric Firewall](https://cwe.mitre.org/data/definitions/1312.html)
- [CWE-1316 — Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges](https://cwe.mitre.org/data/definitions/1316.html)
- [CWE-1326 — Missing Immutable Root of Trust in Hardware](https://cwe.mitre.org/data/definitions/1326.html)

## Prerequisites

- Access to the hardware being leveraged.

## Skills required

- Ability to craft malicious code to inject into the memory region.:LEVEL:Medium
- Intricate knowledge of memory structures.:LEVEL:High

## Mitigations

- Ensure that protected and unprotected memory ranges are isolated and do not overlap.
- If memory regions must overlap, leverage memory priority schemes if memory regions can overlap.
- Ensure that original and mirrored memory regions apply the same p

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
