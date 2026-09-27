# CAPEC-121 — Exploit Non-Production Interfaces

<a id="capec-121"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An adversary exploits a sample, demonstration, test, or debug interface that is unintentionally enabled on a production system, with the goal of gleaning information or leveraging functionality that would otherwise be unavailable.

## Related CWE (10)

[CWE-489](/CWE_REFERENCE.md) [CWE-1209](/CWE_REFERENCE.md) [CWE-1259](/CWE_REFERENCE.md) [CWE-1267](/CWE_REFERENCE.md) [CWE-1270](/CWE_REFERENCE.md) [CWE-1294](/CWE_REFERENCE.md) [CWE-1295](/CWE_REFERENCE.md) [CWE-1296](/CWE_REFERENCE.md) [CWE-1302](/CWE_REFERENCE.md) [CWE-1313](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must have configured non-production interfaces and failed to secure or remove them when brought into a production environment.::

**Skills required:** ::SKILL:Exploiting non-production interfaces requires significant skill and knowledge about the potential non-production interfaces left enabled in pr

**Mitigations:** ::Ensure that production systems do not contain non-production interfaces and that these interfaces are only used in development environments.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
