# CAPEC-25 — Forced Deadlock

<a id="capec-25"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

The adversary triggers and exploits a deadlock condition in the target software to cause a denial of service. A deadlock can occur when two or more competing actions are waiting for each other to finish, and thus neither ever does. Deadlock conditions can be difficult to detect.

## Mapped ATT&CK techniques (1)

- [T1499.004 — Application or System Exploitation](/mitre/techniques/T1499-004.md)

## Related CWE (6)

- [CWE-412 — Unrestricted Externally Accessible Lock](https://cwe.mitre.org/data/definitions/412.html)
- [CWE-567 — Unsynchronized Access to Shared Data in a Multithreaded Context](https://cwe.mitre.org/data/definitions/567.html)
- [CWE-662 — Improper Synchronization](https://cwe.mitre.org/data/definitions/662.html)
- [CWE-667 — Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [CWE-833 — Deadlock](https://cwe.mitre.org/data/definitions/833.html)
- [CWE-1322 — Use of Blocking Code in Single-threaded, Non-blocking Context](https://cwe.mitre.org/data/definitions/1322.html)

## Prerequisites

- The target host has a deadlock condition. There are four conditions for a deadlock to occur, known as the Coffman conditions. [REF-101]
- The target host exposes an API to the user.

## Skills required

- This type of attack may be sophisticated and require knowledge about the system's resources and APIs.:LEVEL:Medium

## Mitigations

- Use known algorithm to avoid deadlock condition (for instance non-blocking synchronization algorithms).
- For competing actions, use well-known libraries which implement synchronization.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
