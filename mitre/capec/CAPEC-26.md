# CAPEC-26 — Leveraging Race Conditions

<a id="capec-26"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

The adversary targets a race condition occurring when multiple processes access and manipulate the same resource concurrently, and the outcome of the execution depends on the particular order in which the access takes place. The adversary can leverage a race condition by "running the race", modifying the resource and modifying the normal execution flow. For instance, a race condition can occur while accessing a file: the adversary can trick the system by replacing the original file with their version and cause the system to read the malicious file.

## Related CWE (12)

- [CWE-368 — Context Switching Race Condition](https://cwe.mitre.org/data/definitions/368.html) — A product performs a series of non-atomic actions to switch between contexts that cross privilege or other security boundaries, but a race condition allows an attacker to modify or misrepresent the product's behavior during the switch.
- [CWE-363 — Race Condition Enabling Link Following](https://cwe.mitre.org/data/definitions/363.html) — The product checks the status of a file or directory before accessing it, which produces a race condition in which the file can be replaced with a link before the access is performed, causing the product to access the wrong file.
- [CWE-366 — Race Condition within a Thread](https://cwe.mitre.org/data/definitions/366.html) — If two threads of execution use a resource simultaneously, there exists the possibility that resources may be used while invalid, in turn making the state of execution undefined.
- [CWE-370 — Missing Check for Certificate Revocation after Initial Check](https://cwe.mitre.org/data/definitions/370.html) — The product does not check the revocation status of a certificate after its initial revocation check, which can cause the product to perform privileged actions even after the certificate is revoked at a later time.
- [CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html) — The product contains a concurrent code sequence that requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence operating concurrently.
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html) — The product utilizes multiple threads, processes, components, or systems to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these actions, which might cause simultaneous accesses of this resource by multiple threads or processes.
- [CWE-689 — Permission Race Condition During Resource Copy](https://cwe.mitre.org/data/definitions/689.html) — The product, while copying or cloning a resource, does not set the resource's permissions or access control until the copy is complete, leaving the resource exposed to other spheres while the copy is taking place.
- [CWE-667 — Improper Locking](https://cwe.mitre.org/data/definitions/667.html) — The product does not properly acquire or release a lock on a resource, leading to unexpected resource state changes and behaviors.
- [CWE-665 — Improper Initialization](https://cwe.mitre.org/data/definitions/665.html) — The product does not initialize or incorrectly initializes a resource, which might leave the resource in an unexpected state when it is accessed or used.
- [CWE-1223 — Race Condition for Write-Once Attributes](https://cwe.mitre.org/data/definitions/1223.html) — A write-once register in hardware design is programmable by an untrusted software component earlier than the trusted software component, resulting in a race condition issue.
- [CWE-1254 — Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html) — The product's comparison logic is performed over a series of steps rather than across the entire string in one operation.
- [CWE-1298 — Hardware Logic Contains Race Conditions](https://cwe.mitre.org/data/definitions/1298.html) — A race condition in the hardware logic results in undermining security guarantees of the system.

## Prerequisites

- A resource is accessed/modified concurrently by multiple processes such that a race condition exists.
- The adversary has the ability to modify the resource.

## Skills required

- [Medium] Being able to "run the race" requires basic knowledge of concurrent processing including synchonization techniques.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data

## Mitigations

- Use safe libraries to access resources such as files.
- Be aware that improper use of access function calls such as chown(), tempfile(), chmod(), etc. can cause a race condition.
- Use synchronization to control the flow of execution.
- Use static analysis tools to find race conditions.
- Pay attention to concurrency problems related to the access of resources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
