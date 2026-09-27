# CAPEC-580 — System Footprinting

<a id="capec-580"></a>

**Abstraction:** Standard  
**Typical severity:** Low  
**Likelihood:** Low

An adversary engages in active probing and exploration activities to determine security information about a remote target system. Often times adversaries will rely on remote applications that can be probed for system configurations.

## Mapped ATT&CK techniques (1)

- [T1082](/mitre/techniques/T1082.md)

## Related CWE (3)

[CWE-204](/CWE_REFERENCE.md) [CWE-205](/CWE_REFERENCE.md) [CWE-208](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have logical access to the target network and system.::

**Skills required:** ::SKILL:The adversary needs to know basic linux commands.:LEVEL:Low::

**Mitigations:** ::Keep patches up to date by installing weekly or daily if possible.::Identify programs that may be used to acquire peripheral information and block them by using a software restriction policy or tools that restrict program execution by using a proce


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
