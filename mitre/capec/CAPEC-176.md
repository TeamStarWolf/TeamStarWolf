# CAPEC-176 — Configuration/Environment Manipulation

<a id="capec-176"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** 

An attacker manipulates files or settings external to a target application which affect the behavior of that application. For example, many applications use external configuration files and libraries - modification of these entities or otherwise affecting the application's ability to use them would constitute a configuration/environment manipulation attack.

## Related CWE (5)

[CWE-15](/CWE_REFERENCE.md) [CWE-1233](/CWE_REFERENCE.md) [CWE-1234](/CWE_REFERENCE.md) [CWE-1304](/CWE_REFERENCE.md) [CWE-1328](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must consult external files or configuration controls to control its execution. All but the very simplest applications meet this requirement.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
