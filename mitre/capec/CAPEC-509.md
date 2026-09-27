# CAPEC-509 — Kerberoasting

<a id="capec-509"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

Through the exploitation of how service accounts leverage Kerberos authentication with Service Principal Names (SPNs), the adversary obtains and subsequently cracks the hashed credentials of a service account target to exploit its privileges. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested ser

## Mapped ATT&CK techniques (1)

- [T1558.003](/mitre/techniques/T1558-003.md)

## Related CWE (7)

[CWE-522](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-521](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary requires access as an authenticated user on the system. This attack pattern relates to elevating privileges.::The adversary requires use of a third-party credential harvesting tool (e.

**Skills required:** ::SKILL::LEVEL:Medium::

**Mitigations:** ::Monitor system and domain logs for abnormal access.::Employ a robust password policy for service accounts. Passwords should be of adequate length and complexity, and they should expire after a period of time.::Employ the principle of least privileg


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
