# CAPEC-560 — Use of Known Domain Credentials

<a id="capec-560"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Stable  

An adversary guesses or obtains (i.e. steals or purchases) legitimate credentials (e.g. userID/password) to achieve authentication and to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (1)

- [T1078 — Valid Accounts](/mitre/techniques/T1078.md)

## Related CWE (8)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)
- [CWE-1273 — Device Unlock Credential Sharing](https://cwe.mitre.org/data/definitions/1273.html)

## Prerequisites

- The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.
- The system/application does not have a sound password policy that is being enforced.
- T

## Skills required

- Once an adversary obtains a known credential, leveraging it is trivial.:LEVEL:Low

## Mitigations

- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Create a strong password policy and ensure that your system enforces this policy.
- Ensure users are not reusing user

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
