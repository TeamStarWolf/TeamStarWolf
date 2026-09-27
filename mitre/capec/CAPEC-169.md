# CAPEC-169 — Footprinting

<a id="capec-169"></a>

**Abstraction:** Meta  
**Typical severity:** Very Low  
**Likelihood:** High

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Mapped ATT&CK techniques (3)

- [T1217](/mitre/techniques/T1217.md)
- [T1592](/mitre/techniques/T1592.md)
- [T1595](/mitre/techniques/T1595.md)

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on co

**Skills required:** ::SKILL:The adversary knows how to send HTTP request, run the scan tool.:LEVEL:Low::

**Mitigations:** ::Keep patches up to date by installing weekly or daily if possible.::Shut down unnecessary services/ports.::Change default passwords by choosing strong passwords.::Curtail unexpected input.::Encrypt and password-protect sensitive data.::Avoid includ


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
