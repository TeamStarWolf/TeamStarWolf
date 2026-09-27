# CAPEC-25 — Forced Deadlock

<a id="capec-25"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Low

The adversary triggers and exploits a deadlock condition in the target software to cause a denial of service. A deadlock can occur when two or more competing actions are waiting for each other to finish, and thus neither ever does. Deadlock conditions can be difficult to detect.

## Mapped ATT&CK techniques (1)

- [T1499.004](/mitre/techniques/T1499-004.md)

## Related CWE (6)

[CWE-412](/CWE_REFERENCE.md) [CWE-567](/CWE_REFERENCE.md) [CWE-662](/CWE_REFERENCE.md) [CWE-667](/CWE_REFERENCE.md) [CWE-833](/CWE_REFERENCE.md) [CWE-1322](/CWE_REFERENCE.md)

**Prerequisites:** ::The target host has a deadlock condition. There are four conditions for a deadlock to occur, known as the Coffman conditions. [REF-101]::The target host exposes an API to the user.::

**Skills required:** ::SKILL:This type of attack may be sophisticated and require knowledge about the system's resources and APIs.:LEVEL:Medium::

**Mitigations:** ::Use known algorithm to avoid deadlock condition (for instance non-blocking synchronization algorithms).::For competing actions, use well-known libraries which implement synchronization.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
