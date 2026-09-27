# CAPEC-565 — Password Spraying

<a id="capec-565"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

In a Password Spraying attack, an adversary tries a small list (e.g. 3-5) of common or expected passwords, often matching the target's complexity policy, against a known list of user accounts to gain valid credentials. The adversary tries a particular password for each user account, before moving onto the next password in the list. This approach assists the adversary in remaining undetected by avo

## Mapped ATT&CK techniques (1)

- [T1110.003](/mitre/techniques/T1110-003.md)

## Related CWE (7)

[CWE-521](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application uses one factor password based authentication.::The system/application does not have a sound password policy that is being enforced.::The system/application does not implement

**Skills required:** ::SKILL:A Password Spraying attack is very straightforward. A variety of password cracking tools are widely available.:LEVEL:Low::

**Mitigations:** ::Create a strong password policy and ensure that your system enforces this policy.::Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
