# CAPEC-176 — Configuration/Environment Manipulation

<a id="capec-176"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

An attacker manipulates files or settings external to a target application which affect the behavior of that application. For example, many applications use external configuration files and libraries - modification of these entities or otherwise affecting the application's ability to use them would constitute a configuration/environment manipulation attack.

## Related CWE (5)

- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
- [CWE-1233 — Security-Sensitive Hardware Controls with Missing Lock Bit Protection](https://cwe.mitre.org/data/definitions/1233.html)
- [CWE-1234 — Hardware Internal or Debug Modes Allow Override of Locks](https://cwe.mitre.org/data/definitions/1234.html)
- [CWE-1304 — Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation](https://cwe.mitre.org/data/definitions/1304.html)
- [CWE-1328 — Security Version Number Mutable to Older Versions](https://cwe.mitre.org/data/definitions/1328.html)

## Prerequisites

- The target application must consult external files or configuration controls to control its execution. All but the very simplest applications meet this requirement.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
