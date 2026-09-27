# CAPEC-653 — Use of Known Operating System Credentials

<a id="capec-653"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An adversary guesses or obtains (i.e. steals or purchases) legitimate operating system credentials (e.g. userID/password) to achieve authentication and to perform authorized actions on the system, under the guise of an authenticated user or service. This applies to any Operating System.

## Related CWE (7)

[CWE-522](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication.::The system/application does not have a sound password policy that is being enforced.::T

**Skills required:** ::SKILL:Once an adversary obtains a known credential, leveraging it is trivial.:LEVEL:Low::

**Mitigations:** ::Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the network.::Create a strong password policy and ensure that your system enforces this policy.::Ensure users are not reusing username/pa


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
