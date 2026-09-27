# CAPEC-138 — Reflection Injection

<a id="capec-138"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** 

An adversary supplies a value to the target application which is then used by reflection methods to identify a class, method, or field. For example, in the Java programming language the reflection libraries permit an application to inspect, load, and invoke classes and their components by name. If an adversary can control the input into these methods including the name of the class/method/field or

## Related CWE (1)

[CWE-470](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must utilize reflection libraries and allow users to directly control the parameters to these methods. If the adversary can host classes where the target can invoke them, more


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
