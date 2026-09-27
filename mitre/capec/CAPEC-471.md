# CAPEC-471 — Search Order Hijacking

<a id="capec-471"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An adversary exploits a weakness in an application's specification of external libraries to exploit the functionality of the loader where the process loading the library searches first in the same directory in which the process binary resides and then in other directories. Exploitation of this preferential search order can allow an attacker to make the loading process load the adversary's rogue li

## Mapped ATT&CK techniques (3)

- [T1574.001](/mitre/techniques/T1574-001.md)
- [T1574.004](/mitre/techniques/T1574-004.md)
- [T1574.008](/mitre/techniques/T1574-008.md)

## Related CWE (1)

[CWE-427](/CWE_REFERENCE.md)

**Prerequisites:** ::Attacker has a mechanism to place its malicious libraries in the needed location on the file system.::

**Skills required:** ::SKILL:Ability to create a malicious library.:LEVEL:Medium::

**Mitigations:** ::Design: Fix the Windows loading process to eliminate the preferential search order by looking for DLLs in the precise location where they are expected::Design: Sign system DLLs so that unauthorized DLLs can be detected.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
