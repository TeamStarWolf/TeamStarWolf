# CAPEC-75 — Manipulating Writeable Configuration Files

<a id="capec-75"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

Generally these are manually edited files that are not in the preview of the system administrators, any ability on the attackers' behalf to modify these files, for example in a CVS repository, gives unauthorized access directly to the application, the same as authorized users.

## Related CWE (6)

- [CWE-349 — Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html)
- [CWE-99 — Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
- [CWE-77 — Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-354 — Improper Validation of Integrity Check Value](https://cwe.mitre.org/data/definitions/354.html)

## Prerequisites

- Configuration files must be modifiable by the attacker

## Skills required

- To identify vulnerable configuration files, and understand how to manipulate servers and erase forensic evidence:LEVEL:Medium

## Mitigations

- Design: Enforce principle of least privilege
- Design: Backup copies of all configuration files
- Implementation: Integrity monitoring for configuration files
- Implementation: Enforce audit logging on code and configuration promotion procedures.
- Imp

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
