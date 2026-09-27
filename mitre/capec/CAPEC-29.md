# CAPEC-29 — Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions

<a id="capec-29"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

This attack targets a race condition occurring between the time of check (state) for a resource and the time of use of a resource. A typical example is file access. The adversary can leverage a file access race condition by "running the race", meaning that they would modify the resource between the first time the target program accesses the file and the time the target program uses the file. During that period of time, the adversary could replace or modify the file, causing the application to behave unexpectedly.

## Related CWE (9)

- [CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html) — The product checks the state of a resource before using that resource, but the resource's state can change between the check and the use in a way that invalidates the results of the check.
- [CWE-368 — Context Switching Race Condition](https://cwe.mitre.org/data/definitions/368.html) — A product performs a series of non-atomic actions to switch between contexts that cross privilege or other security boundaries, but a race condition allows an attacker to modify or misrepresent the product's behavior…
- [CWE-366 — Race Condition within a Thread](https://cwe.mitre.org/data/definitions/366.html) — If two threads of execution use a resource simultaneously, there exists the possibility that resources may be used while invalid, in turn making the state of execution undefined.
- [CWE-370 — Missing Check for Certificate Revocation after Initial Check](https://cwe.mitre.org/data/definitions/370.html) — The product does not check the revocation status of a certificate after its initial revocation check, which can cause the product to perform privileged actions even after the certificate is revoked at a later time.
- [CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html) — The product contains a concurrent code sequence that requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence operating…
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html) — The product utilizes multiple threads, processes, components, or systems to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these…
- [CWE-691 — Insufficient Control Flow Management](https://cwe.mitre.org/data/definitions/691.html) — The code does not sufficiently manage its control flow during execution, creating conditions in which the control flow can be modified in unexpected ways.
- [CWE-663 — Use of a Non-reentrant Function in a Concurrent Context](https://cwe.mitre.org/data/definitions/663.html) — The product calls a non-reentrant function in a concurrent context in which a competing code sequence (e.g. thread or signal handler) may have an opportunity to call the same function or otherwise influence its state.
- [CWE-665 — Improper Initialization](https://cwe.mitre.org/data/definitions/665.html) — The product does not initialize or incorrectly initializes a resource, which might leave the resource in an unexpected state when it is accessed or used.

## Prerequisites

- A resource is access/modified concurrently by multiple processes.
- The adversary is able to modify resource.
- A race condition exists while accessing a resource.

## Skills required

- [Medium] This attack can get sophisticated since the attack has to occur within a short interval of time.

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Alter Execution Logic
- Confidentiality / Read Data
- Availability / Resource Consumption

## Mitigations

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static analysis tools to find race conditions.
- Pay attention to concurrency problems related to the access of resources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
