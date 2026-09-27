# CAPEC-203 — Manipulate Registry Information

<a id="capec-203"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

An adversary exploits a weakness in authorization in order to modify content within a registry (e.g., Windows Registry, Mac plist, application registry). Editing registry information can permit the adversary to hide configuration information or remove indicators of compromise to cover up activity. Many applications utilize registries to store configuration and service information. As such, modific

## Mapped ATT&CK techniques (2)

- [T1112](/mitre/techniques/T1112.md)
- [T1647](/mitre/techniques/T1647.md)

## Related CWE (1)

[CWE-15](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must rely on values stored in a registry.::The adversary must have a means of elevating permissions in order to access and modify registry content through either administrat

**Skills required:** ::SKILL:The adversary requires privileged credentials or the development/acquiring of a tailored remote access tool.:LEVEL:High::

**Mitigations:** ::Ensure proper permissions are set for Registry hives to prevent users from modifying keys.::Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.::Employ robust identification and audit/blocking using 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
