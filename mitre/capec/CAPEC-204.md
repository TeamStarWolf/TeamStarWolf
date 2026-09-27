# CAPEC-204 — Lifting Sensitive Data Embedded in Cache

<a id="capec-204"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary examines a target application's cache, or a browser cache, for sensitive information. Many applications that communicate with remote entities or which perform intensive calculations utilize caches to improve efficiency. However, if the application computes or receives sensitive information and the cache is not appropriately protected, an attacker can browse the cache and retrieve this

## Mapped ATT&CK techniques (1)

- [T1005](/mitre/techniques/T1005.md)

## Related CWE (4)

[CWE-524](/CWE_REFERENCE.md) [CWE-311](/CWE_REFERENCE.md) [CWE-1239](/CWE_REFERENCE.md) [CWE-1258](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must store sensitive information in a cache.::The cache must be inadequately protected against attacker access.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
