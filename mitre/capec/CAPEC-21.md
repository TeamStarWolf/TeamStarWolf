# CAPEC-21 — Exploitation of Trusted Identifiers

<a id="capec-21"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High

An adversary guesses, obtains, or rides a trusted identifier (e.g. session ID, resource ID, cookie, etc.) to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (3)

- [T1134](/mitre/techniques/T1134.md)
- [T1528](/mitre/techniques/T1528.md)
- [T1539](/mitre/techniques/T1539.md)

## Related CWE (9)

[CWE-290](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-539](/CWE_REFERENCE.md) [CWE-6](/CWE_REFERENCE.md) [CWE-384](/CWE_REFERENCE.md) [CWE-664](/CWE_REFERENCE.md) [CWE-602](/CWE_REFERENCE.md) [CWE-642](/CWE_REFERENCE.md)

**Prerequisites:** ::Server software must rely on weak identifier proof and/or verification schemes.::Identifiers must have long lifetimes and potential for reusability.::Server software must allow concurrent sessions t

**Skills required:** ::SKILL:To achieve a direct connection with the weak or non-existent server session access control, and pose as an authorized user:LEVEL:Low::

**Mitigations:** ::Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.::Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many s


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
