# CAPEC-538 — Open-Source Library Manipulation

<a id="capec-538"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

Adversaries implant malicious code in open source software (OSS) libraries to have it widely distributed, as OSS is commonly downloaded by developers and other users to incorporate into software development projects. The adversary can have a particular system in mind to target, or the implantation can be the first stage of follow-on attacks on many systems.

## Mapped ATT&CK techniques (1)

- [T1195.001](/mitre/techniques/T1195-001.md)

## Related CWE (2)

[CWE-494](/CWE_REFERENCE.md) [CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::Access to the open source code base being used by the manufacturer in a system being developed or currently deployed at a victim location.::

**Skills required:** ::SKILL:Advanced knowledge about the inclusion and specific usage of an open source code project within system being targeted for infiltration.:LEVEL:


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
