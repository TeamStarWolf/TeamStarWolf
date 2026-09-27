# CAPEC-55 — Rainbow Table Password Cracking

<a id="capec-55"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

An attacker gets access to the database table where hashes of passwords are stored. They then use a rainbow table of pre-computed hash chains to attempt to look up the original password. Once the original password corresponding to the hash is obtained, the attacker uses the original password to gain access to the system.

## Mapped ATT&CK techniques (1)

- [T1110.002](/mitre/techniques/T1110-002.md)

## Related CWE (8)

[CWE-261](/CWE_REFERENCE.md) [CWE-521](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-916](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md)

**Prerequisites:** ::Hash of the original password is available to the attacker. For a better chance of success, an attacker should have more than one hash of the original password, and ideally the whole table.::Salt wa

**Skills required:** ::SKILL:A variety of password cracking tools are available that can leverage a rainbow table. The more difficult part is to obtain the password hash(e

**Mitigations:** ::Use salt when computing password hashes. That is, concatenate the salt (random bits) with the original password prior to hashing it.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
