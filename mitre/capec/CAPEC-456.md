# CAPEC-456 — Infected Memory

<a id="capec-456"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary inserts malicious logic into memory enabling them to achieve a negative impact. This logic is often hidden from the user of the system and works behind the scenes to achieve negative impacts. This pattern of attack focuses on systems already fielded and used in operation as opposed to systems that are still under development and part of the supply chain.

## Related CWE (5)

- [CWE-1257 — Improper Access Control Applied to Mirrored or Aliased Memory Regions](https://cwe.mitre.org/data/definitions/1257.html)
- [CWE-1260 — Improper Handling of Overlap Between Protected Memory Ranges](https://cwe.mitre.org/data/definitions/1260.html)
- [CWE-1274 — Improper Access Control for Volatile Memory Containing Boot Code](https://cwe.mitre.org/data/definitions/1274.html)
- [CWE-1312 — Missing Protection for Mirrored Regions in On-Chip Fabric Firewall](https://cwe.mitre.org/data/definitions/1312.html)
- [CWE-1316 — Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges](https://cwe.mitre.org/data/definitions/1316.html)

## Mitigations

- Leverage anti-virus products to detect stop operations with known virus.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
