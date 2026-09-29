# CAPEC-25 — Forced Deadlock

<a id="capec-25"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary triggers and exploits a deadlock condition in the target software to cause a denial of service. A deadlock can occur when two or more competing actions are waiting for each other to finish, and thus neither ever does. Deadlock conditions can be difficult to detect.

## Mapped ATT&CK techniques (1)

- [T1499.004 — Application or System Exploitation](/mitre/techniques/T1499-004.md) — Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users.

## Related CWE (6)

- [CWE-412 — Unrestricted Externally Accessible Lock](https://cwe.mitre.org/data/definitions/412.html) — The product properly checks for the existence of a lock, but the lock can be externally controlled or influenced by an actor that is outside of the intended sphere of control.
- [CWE-567 — Unsynchronized Access to Shared Data in a Multithreaded Context](https://cwe.mitre.org/data/definitions/567.html) — The product does not properly synchronize shared data, such as static variables across threads, which can lead to undefined behavior and unpredictable data changes.
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html) — The product utilizes multiple threads, processes, components, or systems to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these actions, which might cause simultaneous accesses of this resource by multiple threads or processes.
- [CWE-667 — Improper Locking](https://cwe.mitre.org/data/definitions/667.html) — The product does not properly acquire or release a lock on a resource, leading to unexpected resource state changes and behaviors.
- [CWE-833 — Deadlock](https://cwe.mitre.org/data/definitions/833.html) — The product contains multiple threads or executable segments that are waiting for each other to release a necessary lock, resulting in deadlock.
- [CWE-1322 — Use of Blocking Code in Single-threaded, Non-blocking Context](https://cwe.mitre.org/data/definitions/1322.html) — The product uses a non-blocking model that relies on a single threaded process for features such as scalability, but it contains code that can block when it is invoked.

## Prerequisites

- The target host has a deadlock condition. There are four conditions for a deadlock to occur, known as the Coffman conditions. [REF-101]
- The target host exposes an API to the user.

## Skills required

- [Medium] This type of attack may be sophisticated and require knowledge about the system's resources and APIs.

## Consequences

- Availability / Resource Consumption

## Mitigations

- Use known algorithm to avoid deadlock condition (for instance non-blocking synchronization algorithms).
- For competing actions, use well-known libraries which implement synchronization.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
