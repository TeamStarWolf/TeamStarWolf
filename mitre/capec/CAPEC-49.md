# CAPEC-49 — Password Brute Forcing

<a id="capec-49"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary tries every possible value for a password until they succeed. A brute force attack, if feasible computationally, will always be successful because it will essentially go through all possible passwords given the alphabet used (lower case letters, upper case letters, numbers, symbols, etc.) and the maximum length of the password.

## Mapped ATT&CK techniques (1)

- [T1110.001 — Password Guessing](/mitre/techniques/T1110-001.md) — Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.

## Related CWE (8)

- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) — The product does not require that users should have strong passwords.
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html) — The product does not have a mechanism in place for managing password aging.
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html) — The product supports password aging, but the expiration period is too long.
- [CWE-257 — Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html) — The storage of passwords in a recoverable format makes them subject to password reuse attacks by malicious users.
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html) — A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.
- [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) — The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html) — The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html) — The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

## Prerequisites

- An adversary needs to know a username to target.
- The system uses password based authentication as the one factor authentication mechanism.
- An application does not have a password throttling mechanism in place. A good password throttling mechanism will make it almost impossible computationally to brute force a password as it may either lock out the user after a certain number of incorrect attempts or introduce time out periods. Both of these would make a brute force attack impractical.

## Skills required

- [Low] A brute force attack is very straightforward. A variety of password cracking tools are widely available.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.
- Put together a strong password policy and make sure that all user created passwords comply with it. Alternatively automatically generate strong passwords for users.
- Passwords need to be recycled to prevent aging, that is every once in a while a new password must be chosen.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
