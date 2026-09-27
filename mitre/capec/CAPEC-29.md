# CAPEC-29 — Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions

<a id="capec-29"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets a race condition occurring between the time of check (state) for a resource and the time of use of a resource. A typical example is file access. The adversary can leverage a file access race condition by running the race, meaning that they would modify the resource between the first time the target program accesses the file and the time the target program uses the file. During

## Related CWE (9)

- [CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-368 — Context Switching Race Condition](https://cwe.mitre.org/data/definitions/368.html)
- [CWE-366 — Race Condition within a Thread](https://cwe.mitre.org/data/definitions/366.html)
- [CWE-370 — Missing Check for Certificate Revocation after Initial Check](https://cwe.mitre.org/data/definitions/370.html)
- [CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html)
- [CWE-691 — Insufficient Control Flow Management](https://cwe.mitre.org/data/definitions/691.html)
- [CWE-663 — Use of a Non-reentrant Function in a Concurrent Context](https://cwe.mitre.org/data/definitions/663.html)
- [CWE-665 — Improper Initialization](https://cwe.mitre.org/data/definitions/665.html)

## Prerequisites

- A resource is access/modified concurrently by multiple processes.
- The adversary is able to modify resource.
- A race condition exists while accessing a resource.

## Skills required

- This attack can get sophisticated since the attack has to occur within a short interval of time.:LEVEL:Medium

## Mitigations

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static ana

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
