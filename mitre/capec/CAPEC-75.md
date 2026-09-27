# CAPEC-75 — Manipulating Writeable Configuration Files

<a id="capec-75"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

Generally these are manually edited files that are not in the preview of the system administrators, any ability on the attackers' behalf to modify these files, for example in a CVS repository, gives unauthorized access directly to the application, the same as authorized users.

## Related CWE (6)

[CWE-349](/CWE_REFERENCE.md) [CWE-99](/CWE_REFERENCE.md) [CWE-77](/CWE_REFERENCE.md) [CWE-346](/CWE_REFERENCE.md) [CWE-353](/CWE_REFERENCE.md) [CWE-354](/CWE_REFERENCE.md)

**Prerequisites:** ::Configuration files must be modifiable by the attacker::

**Skills required:** ::SKILL:To identify vulnerable configuration files, and understand how to manipulate servers and erase forensic evidence:LEVEL:Medium::

**Mitigations:** ::Design: Enforce principle of least privilege::Design: Backup copies of all configuration files::Implementation: Integrity monitoring for configuration files::Implementation: Enforce audit logging on code and configuration promotion procedures.::Imp


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
