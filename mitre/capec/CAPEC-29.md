# CAPEC-29 — Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions

<a id="capec-29"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

This attack targets a race condition occurring between the time of check (state) for a resource and the time of use of a resource. A typical example is file access. The adversary can leverage a file access race condition by running the race, meaning that they would modify the resource between the first time the target program accesses the file and the time the target program uses the file. During

## Related CWE (9)

[CWE-367](/CWE_REFERENCE.md) [CWE-368](/CWE_REFERENCE.md) [CWE-366](/CWE_REFERENCE.md) [CWE-370](/CWE_REFERENCE.md) [CWE-362](/CWE_REFERENCE.md) [CWE-662](/CWE_REFERENCE.md) [CWE-691](/CWE_REFERENCE.md) [CWE-663](/CWE_REFERENCE.md) [CWE-665](/CWE_REFERENCE.md)

**Prerequisites:** ::A resource is access/modified concurrently by multiple processes.::The adversary is able to modify resource.::A race condition exists while accessing a resource.::

**Skills required:** ::SKILL:This attack can get sophisticated since the attack has to occur within a short interval of time.:LEVEL:Medium::

**Mitigations:** ::Use safe libraries to access resources such as files.::Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.::Use synchronization to control the flow of execution.::Use static ana


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
