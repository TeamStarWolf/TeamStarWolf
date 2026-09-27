# CAPEC-652 — Use of Known Kerberos Credentials

<a id="capec-652"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary obtains (i.e. steals or purchases) legitimate Kerberos credentials (e.g. Kerberos service account userID/password or Kerberos Tickets) with the goal of achieving authenticated access to additional systems, applications, or services within the domain.

## Mapped ATT&CK techniques (1)

- [T1558 — Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md)

## Related CWE (9)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)
- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-836 — Use of Password Hash Instead of Password for Authentication](https://cwe.mitre.org/data/definitions/836.html)

## Prerequisites

- The system/application leverages Kerberos authentication.
- The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication for Kerberos service accounts.

## Skills required

- Once an adversary obtains a known Kerberos credential, leveraging it is trivial.:LEVEL:Low

## Mitigations

- Create a strong password policy and ensure that your system enforces this policy for Kerberos service accounts.
- Ensure Kerberos service accounts are not reusing username/password combinations for multiple systems, applications, or services.
- Do no

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
