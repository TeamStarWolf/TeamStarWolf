# CAPEC-538 — Open-Source Library Manipulation

<a id="capec-538"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

Adversaries implant malicious code in open source software (OSS) libraries to have it widely distributed, as OSS is commonly downloaded by developers and other users to incorporate into software development projects. The adversary can have a particular system in mind to target, or the implantation can be the first stage of follow-on attacks on many systems.

## Mapped ATT&CK techniques (1)

- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md)

## Related CWE (2)

- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Prerequisites

- Access to the open source code base being used by the manufacturer in a system being developed or currently deployed at a victim location.

## Skills required

- Advanced knowledge about the inclusion and specific usage of an open source code project within system being targeted for infiltration.:LEVEL:

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
