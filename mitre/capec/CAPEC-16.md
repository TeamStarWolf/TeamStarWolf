# CAPEC-16 — Dictionary-based Password Attack

<a id="capec-16"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user's account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern. Dictionary Attacks differ from similar attacks such as Password Spra

## Related CWE (7)

[CWE-521](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md)

**Prerequisites:** ::The system uses one factor password based authentication.::The system does not have a sound password policy that is being enforced.::The system does not implement an effective password throttling me

**Skills required:** ::SKILL:A variety of password cracking tools and dictionaries are available to launch this type of an attack.:LEVEL:Low::

**Mitigations:** ::Create a strong password policy and ensure that your system enforces this policy.::Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
