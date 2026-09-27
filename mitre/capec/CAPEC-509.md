# CAPEC-509 — Kerberoasting

<a id="capec-509"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Stable  

Through the exploitation of how service accounts leverage Kerberos authentication with Service Principal Names (SPNs), the adversary obtains and subsequently cracks the hashed credentials of a service account target to exploit its privileges. The Kerberos authentication protocol centers around a ticketing system which is used to request/grant access to services and to then access the requested ser

## Mapped ATT&CK techniques (1)

- [T1558.003 — Kerberoasting](/mitre/techniques/T1558-003.md)

## Related CWE (7)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

## Prerequisites

- The adversary requires access as an authenticated user on the system. This attack pattern relates to elevating privileges.
- The adversary requires use of a third-party credential harvesting tool (e.

## Skills required

- SKILL
- Medium

## Mitigations

- Monitor system and domain logs for abnormal access.
- Employ a robust password policy for service accounts. Passwords should be of adequate length and complexity, and they should expire after a period of time.
- Employ the principle of least privileg

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
