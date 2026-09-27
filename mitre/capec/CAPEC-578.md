# CAPEC-578 — Disable Security Software

<a id="capec-578"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary exploits a weakness in access control to disable security tools so that detection does not occur. This can take the form of killing processes, deleting registry keys so that tools do not start at run time, deleting log files, or other methods.

## Mapped ATT&CK techniques (7)

- [T1556.006](/mitre/techniques/T1556-006.md)
- [T1562.001](/mitre/techniques/T1562-001.md)
- [T1562.002](/mitre/techniques/T1562-002.md)
- [T1562.004](/mitre/techniques/T1562-004.md)
- [T1562.007](/mitre/techniques/T1562-007.md)
- [T1562.008](/mitre/techniques/T1562-008.md)
- [T1562.009](/mitre/techniques/T1562-009.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have the capability to interact with the configuration of the targeted system.::

**Mitigations:** ::Ensure proper permissions are in place to prevent adversaries from altering the execution status of security tools.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
