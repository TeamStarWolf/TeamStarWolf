# CAPEC-2 — Inducing Account Lockout

<a id="capec-2"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High

An attacker leverages the security functionality of the system aimed at thwarting potential attacks to launch a denial of service attack against a legitimate system user. Many systems, for instance, implement a password throttling mechanism that locks an account after a certain number of incorrect log in attempts. An attacker can leverage this throttling mechanism to lock a legitimate user out of

## Mapped ATT&CK techniques (1)

- [T1531](/mitre/techniques/T1531.md)

## Related CWE (1)

[CWE-645](/CWE_REFERENCE.md)

**Prerequisites:** ::The system has a lockout mechanism.::An attacker must be able to reproduce behavior that would result in an account being locked.::

**Skills required:** ::SKILL:No programming skills or computer knowledge is needed. An attacker can easily use this attack pattern following the Execution Flow above.:LEVE

**Mitigations:** ::Implement intelligent password throttling mechanisms such as those which take IP address into account, in addition to the login name.::When implementing security features, consider how they can be misused and made to turn on themselves.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
