# CAPEC-26 — Leveraging Race Conditions

<a id="capec-26"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

The adversary targets a race condition occurring when multiple processes access and manipulate the same resource concurrently, and the outcome of the execution depends on the particular order in which the access takes place. The adversary can leverage a race condition by running the race, modifying the resource and modifying the normal execution flow. For instance, a race condition can occur while

## Related CWE (12)

- [CWE-368 — Context Switching Race Condition](https://cwe.mitre.org/data/definitions/368.html)
- [CWE-363 — Race Condition Enabling Link Following](https://cwe.mitre.org/data/definitions/363.html)
- [CWE-366 — Race Condition within a Thread](https://cwe.mitre.org/data/definitions/366.html)
- [CWE-370 — Missing Check for Certificate Revocation after Initial Check](https://cwe.mitre.org/data/definitions/370.html)
- [CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html)
- [CWE-689 — Permission Race Condition During Resource Copy](https://cwe.mitre.org/data/definitions/689.html)
- [CWE-667 — Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [CWE-665 — Improper Initialization](https://cwe.mitre.org/data/definitions/665.html)
- [CWE-1223 — Race Condition for Write-Once Attributes](https://cwe.mitre.org/data/definitions/1223.html)
- [CWE-1254 — Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html)
- [CWE-1298 — Hardware Logic Contains Race Conditions](https://cwe.mitre.org/data/definitions/1298.html)

## Prerequisites

- A resource is accessed/modified concurrently by multiple processes such that a race condition exists.
- The adversary has the ability to modify the resource.

## Skills required

- Being able to run the race requires basic knowledge of concurrent processing including synchonization techniques.:LEVEL:Medium

## Mitigations

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static ana

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
