# CAPEC-55 — Rainbow Table Password Cracking

<a id="capec-55"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An attacker gets access to the database table where hashes of passwords are stored. They then use a rainbow table of pre-computed hash chains to attempt to look up the original password. Once the original password corresponding to the hash is obtained, the attacker uses the original password to gain access to the system.

## Mapped ATT&CK techniques (1)

- [T1110.002 — Password Cracking](/mitre/techniques/T1110-002.md)

## Related CWE (8)

- [CWE-261 — Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
- [CWE-521 — Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-262 — Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)
- [CWE-263 — Password Aging with Long Expiration](https://cwe.mitre.org/data/definitions/263.html)
- [CWE-654 — Reliance on a Single Factor in a Security Decision](https://cwe.mitre.org/data/definitions/654.html)
- [CWE-916 — Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-308 — Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 — Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

## Prerequisites

- Hash of the original password is available to the attacker. For a better chance of success, an attacker should have more than one hash of the original password, and ideally the whole table.
- Salt wa

## Skills required

- A variety of password cracking tools are available that can leverage a rainbow table. The more difficult part is to obtain the password hash(e

## Mitigations

- Use salt when computing password hashes. That is, concatenate the salt (random bits) with the original password prior to hashing it.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
