# CAPEC-560 — Use of Known Domain Credentials

<a id="capec-560"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** High

An adversary guesses or obtains (i.e. steals or purchases) legitimate credentials (e.g. userID/password) to achieve authentication and to perform authorized actions under the guise of an authenticated user or service.

## Mapped ATT&CK techniques (1)

- [T1078](/mitre/techniques/T1078.md)

## Related CWE (8)

[CWE-522](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-1273](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.::The system/application does not have a sound password policy that is being enforced.::T

**Skills required:** ::SKILL:Once an adversary obtains a known credential, leveraging it is trivial.:LEVEL:Low::

**Mitigations:** ::Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.::Create a strong password policy and ensure that your system enforces this policy.::Ensure users are not reusing user


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
