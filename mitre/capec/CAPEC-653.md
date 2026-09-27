# CAPEC-653 — Use of Known Operating System Credentials

<a id="capec-653"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary guesses or obtains (i.e. steals or purchases) legitimate operating system credentials (e.g. userID/password) to achieve authentication and to perform authorized actions on the system, under the guise of an authenticated user or service. This applies to any Operating System.

## Related CWE (7)

- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)

## Prerequisites

- The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication.
- The system/application does not have a sound password policy that is being enforced.
- T

## Skills required

- Once an adversary obtains a known credential, leveraging it is trivial.:LEVEL:Low

## Mitigations

- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the network.
- Create a strong password policy and ensure that your system enforces this policy.
- Ensure users are not reusing username/pa

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
