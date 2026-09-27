# CAPEC-652 — Use of Known Kerberos Credentials

<a id="capec-652"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary obtains (i.e. steals or purchases) legitimate Kerberos credentials (e.g. Kerberos service account userID/password or Kerberos Tickets) with the goal of achieving authenticated access to additional systems, applications, or services within the domain.

## Mapped ATT&CK techniques (1)

- [T1558](/mitre/techniques/T1558.md)

## Related CWE (9)

[CWE-522](/CWE_REFERENCE.md) [CWE-307](/CWE_REFERENCE.md) [CWE-308](/CWE_REFERENCE.md) [CWE-309](/CWE_REFERENCE.md) [CWE-262](/CWE_REFERENCE.md) [CWE-263](/CWE_REFERENCE.md) [CWE-654](/CWE_REFERENCE.md) [CWE-294](/CWE_REFERENCE.md) [CWE-836](/CWE_REFERENCE.md)

**Prerequisites:** ::The system/application leverages Kerberos authentication.::The system/application uses one factor password-based authentication, SSO, and/or cloud-based authentication for Kerberos service accounts.

**Skills required:** ::SKILL:Once an adversary obtains a known Kerberos credential, leveraging it is trivial.:LEVEL:Low::

**Mitigations:** ::Create a strong password policy and ensure that your system enforces this policy for Kerberos service accounts.::Ensure Kerberos service accounts are not reusing username/password combinations for multiple systems, applications, or services.::Do no


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
