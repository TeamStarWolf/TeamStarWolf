# CAPEC-50 — Password Recovery Exploitation

<a id="capec-50"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An attacker may take advantage of the application feature to help users recover their forgotten passwords in order to gain access into the system with the same privileges as the original user. Generally password recovery schemes tend to be weak and insecure.

## Related CWE (2)

[CWE-522](/CWE_REFERENCE.md) [CWE-640](/CWE_REFERENCE.md)

**Prerequisites:** ::The system allows users to recover their passwords and gain access back into the system.::Password recovery mechanism has been designed or implemented insecurely.::Password recovery mechanism relies

**Skills required:** ::SKILL:Brute force attack:LEVEL:Low::SKILL:Social engineering and more sophisticated technical attacks.:LEVEL:Medium::

**Mitigations:** ::Use multiple security questions (e.g. have three and make the user answer two of them correctly). Let the user select their own security questions or provide them with choices of questions that are not generic.::E-mail the temporary password to the


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
