# CAPEC-565 — Password Spraying

<a id="capec-565"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

In a Password Spraying attack, an adversary tries a small list (e.g. 3-5) of common or expected passwords, often matching the target's complexity policy, against a known list of user accounts to gain valid credentials. The adversary tries a particular password for each user account, before moving onto the next password in the list. This approach assists the adversary in remaining undetected by avo

## Mapped ATT&CK techniques (1)

- [T1110.003 — Password Spraying](/mitre/techniques/T1110-003.md)

## Related CWE (7)

- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

## Prerequisites

- The system/application uses one factor password based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement

## Skills required

- A Password Spraying attack is very straightforward. A variety of password cracking tools are widely available.:LEVEL:Low

## Mitigations

- Create a strong password policy and ensure that your system enforces this policy.
- Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
