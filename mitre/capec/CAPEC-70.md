# CAPEC-70 — Try Common or Default Usernames and Passwords

<a id="capec-70"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary may try certain common or default usernames and passwords to gain access into the system and perform unauthorized actions. An adversary may try an intelligent brute force using empty passwords, known vendor default credentials, as well as a dictionary of common usernames and passwords. Many vendor products come preconfigured with default (and thus well-known) usernames and passwords t

## Mapped ATT&CK techniques (1)

- [T1078.001](/mitre/techniques/T1078-001.md)

## Related CWE (7)

[CWE-521](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-798](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md)

**Prerequisites:** ::The system uses one factor password based authentication.The adversary has the means to interact with the system.::

**Skills required:** ::SKILL:An adversary just needs to gain access to common default usernames/passwords specific to the technologies used by the system. Additionally, a 

**Mitigations:** ::Delete all default account credentials that may be put in by the product vendor.::Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.::Put together a strong passwor


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
