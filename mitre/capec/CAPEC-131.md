# CAPEC-131 — Resource Leak Exposure

<a id="capec-131"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Stable  

An adversary utilizes a resource leak on the target to deplete the quantity of the resource available to service legitimate requests.

## Mapped ATT&CK techniques (1)

- [T1499 — Endpoint Denial of Service](/mitre/techniques/T1499.md) — Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.

## Related CWE (1)

- [CWE-404 — Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html) — The product does not release or incorrectly releases a resource before it is made available for re-use.

## Prerequisites

- The target must have a resource leak that the adversary can repeatedly trigger.

## Consequences

- Availability / Unreliable Execution, Resource Consumption

## Mitigations

- If possible, leverage coding language(s) that do not allow this weakness to occur (e.g., Java, Ruby, and Python all perform automatic garbage collection that releases memory for objects that have been deallocated).
- Memory should always be allocated/freed using matching functions (e.g., malloc/free, new/delete, etc.)
- Implement best practices with respect to memory management, including the freeing of all allocated resources at all exit points and ensuring consistency with how and where memory is freed in a function.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
