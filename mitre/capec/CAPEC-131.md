# CAPEC-131 — Resource Leak Exposure

<a id="capec-131"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary utilizes a resource leak on the target to deplete the quantity of the resource available to service legitimate requests.

## Mapped ATT&CK techniques (1)

- [T1499](/mitre/techniques/T1499.md)

## Related CWE (1)

[CWE-404](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must have a resource leak that the adversary can repeatedly trigger.::

**Mitigations:** ::If possible, leverage coding language(s) that do not allow this weakness to occur (e.g., Java, Ruby, and Python all perform automatic garbage collection that releases memory for objects that have been deallocated).::Memory should always be allocate


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
