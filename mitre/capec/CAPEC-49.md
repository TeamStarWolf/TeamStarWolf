# CAPEC-49 — Password Brute Forcing

<a id="capec-49"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary tries every possible value for a password until they succeed. A brute force attack, if feasible computationally, will always be successful because it will essentially go through all possible passwords given the alphabet used (lower case letters, upper case letters, numbers, symbols, etc.) and the maximum length of the password.

## Mapped ATT&CK techniques (1)

- [T1110.001](/mitre/techniques/T1110-001.md)

## Related CWE (8)

[CWE-521](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-257](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md)

**Prerequisites:** ::An adversary needs to know a username to target.::The system uses password based authentication as the one factor authentication mechanism.::An application does not have a password throttling mechan

**Skills required:** ::SKILL:A brute force attack is very straightforward. A variety of password cracking tools are widely available.:LEVEL:Low::

**Mitigations:** ::Implement a password throttling mechanism. This mechanism should take into account both the IP address and the log in name of the user.::Put together a strong password policy and make sure that all user created passwords comply with it. Alternative


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
