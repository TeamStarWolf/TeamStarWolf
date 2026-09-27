# CAPEC-203 — Manipulate Registry Information

<a id="capec-203"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Stable  

An adversary exploits a weakness in authorization in order to modify content within a registry (e.g., Windows Registry, Mac plist, application registry). Editing registry information can permit the adversary to hide configuration information or remove indicators of compromise to cover up activity. Many applications utilize registries to store configuration and service information. As such, modific

## Mapped ATT&CK techniques (2)

- [T1112 — Modify Registry](/mitre/techniques/T1112.md) — Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.
- [T1647 — Plist File Modification](/mitre/techniques/T1647.md) — Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses.

## Related CWE (1)

- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html) — One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- The targeted application must rely on values stored in a registry.
- The adversary must have a means of elevating permissions in order to access and modify registry content through either administrat

## Skills required

- The adversary requires privileged credentials or the development/acquiring of a tailored remote access tool.:LEVEL:High

## Mitigations

- Ensure proper permissions are set for Registry hives to prevent users from modifying keys.
- Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.
- Employ robust identification and audit/blocking using

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
