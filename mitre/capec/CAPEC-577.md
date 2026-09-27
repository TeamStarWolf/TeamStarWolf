# CAPEC-577 — Owner Footprinting

<a id="capec-577"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Draft  

An adversary exploits functionality meant to identify information about the primary users on the target system to an authorized user. They may do this, for example, by reviewing logins or file modification times. By knowing what owners use the target system, the adversary can inform further and more targeted malicious behavior. An example Windows command that may accomplish this is dir /A ntuser.d

## Mapped ATT&CK techniques (1)

- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md)

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The adversary must have gained access to the target system via physical or logical means in order to carry out this attack.
- Administrator permissions are required to view the home folder of other u

## Mitigations

- Ensure that proper permissions on files and folders are enacted to limit accessibility.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
