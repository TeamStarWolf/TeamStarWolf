# CAPEC-26 — Leveraging Race Conditions

<a id="capec-26"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High

The adversary targets a race condition occurring when multiple processes access and manipulate the same resource concurrently, and the outcome of the execution depends on the particular order in which the access takes place. The adversary can leverage a race condition by running the race, modifying the resource and modifying the normal execution flow. For instance, a race condition can occur while

## Related CWE (12)

[CWE-368](/CWE_REFERENCE.md) [CWE-363](/CWE_REFERENCE.md) [CWE-366](/CWE_REFERENCE.md) [CWE-370](/CWE_REFERENCE.md) [CWE-362](/CWE_REFERENCE.md) [CWE-662](/CWE_REFERENCE.md) [CWE-689](/CWE_REFERENCE.md) [CWE-667](/CWE_REFERENCE.md) [CWE-665](/CWE_REFERENCE.md) [CWE-1223](/CWE_REFERENCE.md) [CWE-1254](/CWE_REFERENCE.md) [CWE-1298](/CWE_REFERENCE.md)

**Prerequisites:** ::A resource is accessed/modified concurrently by multiple processes such that a race condition exists.::The adversary has the ability to modify the resource.::

**Skills required:** ::SKILL:Being able to run the race requires basic knowledge of concurrent processing including synchonization techniques.:LEVEL:Medium::

**Mitigations:** ::Use safe libraries to access resources such as files.::Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.::Use synchronization to control the flow of execution.::Use static ana


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
