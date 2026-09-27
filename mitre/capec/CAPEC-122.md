# CAPEC-122 — Privilege Abuse

<a id="capec-122"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources.

## Mapped ATT&CK techniques (1)

- [T1548](/mitre/techniques/T1548.md)

## Related CWE (3)

[CWE-269](/CWE_REFERENCE.md) [CWE-732](/CWE_REFERENCE.md) [CWE-1317](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must have misconfigured their access control mechanisms such that sensitive information, which should only be accessible to more trusted users, remains accessible to less trusted users.::

**Skills required:** ::SKILL:Adversary can leverage privileged features they already have access to without additional effort or skill. Adversary is only required to have 

**Mitigations:** ::Configure account privileges such privileged/administrator functionality is not exposed to non-privileged/lower accounts.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
