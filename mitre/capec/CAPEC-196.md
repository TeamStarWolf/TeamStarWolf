# CAPEC-196 — Session Credential Falsification through Forging

<a id="capec-196"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium

An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to by

## Mapped ATT&CK techniques (3)

- [T1134.002](/mitre/techniques/T1134-002.md)
- [T1134.003](/mitre/techniques/T1134-003.md)
- [T1606](/mitre/techniques/T1606.md)

## Related CWE (2)

[CWE-384](/CWE_REFERENCE.md) [CWE-664](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must use session credentials to identify legitimate users. Session identifiers that remains unchanged when the privilege levels change. Predictable session identifiers.::

**Skills required:** ::SKILL:Forge the session credential and reply the request.:LEVEL:Medium::

**Mitigations:** ::Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or g


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
