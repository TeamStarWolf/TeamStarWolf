# CAPEC-124 — Shared Resource Manipulation

<a id="capec-124"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** 

An adversary exploits a resource shared between multiple applications, an application pool or hardware pin multiplexing to affect behavior. Resources may be shared between multiple applications or between multiple threads of a single application. Resource sharing is usually accomplished through mutual access to a single memory location or multiplexed hardware pins. If an adversary can manipulate t

## Related CWE (2)

[CWE-1189](/CWE_REFERENCE.md) [CWE-1331](/CWE_REFERENCE.md)

**Prerequisites:** ::The target applications, threads or functions must share resources between themselves.::The adversary must be able to manipulate some piece of the shared resource either directly or indirectly and t


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
