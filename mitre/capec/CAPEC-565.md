# CAPEC-565 — Password Spraying

<a id="capec-565"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

In a Password Spraying attack, an adversary tries a small list (e.g. 3-5) of common or expected passwords, often matching the target's complexity policy, against a known list of user accounts to gain valid credentials. The adversary tries a particular password for each user account, before moving onto the next password in the list. This approach assists the adversary in remaining undetected by avo

## Mapped ATT&CK techniques (1)

- [T1110.003 — Password Spraying](/mitre/techniques/T1110-003.md) — Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.

## Related CWE (7)

- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) — The product does not require that users should have strong passwords.
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html) — The product does not have a mechanism in place for managing password aging.
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html) — The product supports password aging, but the expiration period is too long.
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html) — A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted…
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) — The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html) — The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html) — The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

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
