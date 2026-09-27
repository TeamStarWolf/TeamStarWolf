# CAPEC-600 — Credential Stuffing

<a id="capec-600"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary tries known username/password combinations against different systems, applications, or services to gain additional authenticated access. Credential Stuffing attacks rely upon the fact that many users leverage the same username/password combination for multiple systems, applications, and services.

## Mapped ATT&CK techniques (1)

- [T1110.004](/mitre/techniques/T1110-004.md)

## Related CWE (7)

[CWE-522](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.::The system/application does not have a sound password policy that is being enforced.::T

**Skills required:** ::SKILL:A Credential Stuffing attack is very straightforward.:LEVEL:Low::

**Mitigations:** ::Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.::Create a strong password policy and ensure that your system enforces this policy.::Ensure users are not reusing user


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
