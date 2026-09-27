# CAPEC-49 — Password Brute Forcing

<a id="capec-49"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary tries every possible value for a password until they succeed. A brute force attack, if feasible computationally, will always be successful because it will essentially go through all possible passwords given the alphabet used (lower case letters, upper case letters, numbers, symbols, etc.) and the maximum length of the password.

## Mapped ATT&CK techniques (1)

- [T1110.001 — Password Guessing](/mitre/techniques/T1110-001.md)

## Related CWE (8)

- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-257 — Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

## Prerequisites

- An adversary needs to know a username to target.
- The system uses password based authentication as the one factor authentication mechanism.
- An application does not have a password throttling mechan

## Skills required

- A brute force attack is very straightforward. A variety of password cracking tools are widely available.:LEVEL:Low

## Mitigations

- Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.
- Put together a strong password policy and make sure that all user created passwords comply with it. Alternative

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
