# CAPEC-647 — Collect Data from Registries

<a id="capec-647"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary exploits a weakness in authorization to gather system-specific data and sensitive information within a registry (e.g., Windows Registry, Mac plist). These contain information about the system configuration, software, operating system, and security. The adversary can leverage information gathered in order to carry out further attacks.

## Mapped ATT&CK techniques (3)

- [T1005](/mitre/techniques/T1005.md)
- [T1012](/mitre/techniques/T1012.md)
- [T1552.002](/mitre/techniques/T1552-002.md)

## Related CWE (1)

[CWE-285](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).::The adversary must have capability to navigate the op

**Skills required:** ::SKILL:Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only the capability 

**Mitigations:** ::Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.::Employ robust identification and audit/blocking via using an allowlist of applications on your system. Unnecessary applications, utilities, and co


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
