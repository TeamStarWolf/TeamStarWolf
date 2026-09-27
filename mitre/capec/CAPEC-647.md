# CAPEC-647 — Collect Data from Registries

<a id="capec-647"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An adversary exploits a weakness in authorization to gather system-specific data and sensitive information within a registry (e.g., Windows Registry, Mac plist). These contain information about the system configuration, software, operating system, and security. The adversary can leverage information gathered in order to carry out further attacks.

## Mapped ATT&CK techniques (3)

- [T1005 — Data from Local System](/mitre/techniques/T1005.md) — Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.
- [T1012 — Query Registry](/mitre/techniques/T1012.md) — Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
- [T1552.002 — Credentials in Registry](/mitre/techniques/T1552-002.md) — Adversaries may search the Registry on compromised systems for insecurely stored credentials.

## Related CWE (1)

- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- The adversary must have obtained logical access to the system by some means (e.g., via obtained credentials or planting malware on the system).
- The adversary must have capability to navigate the operating system to peruse the registry.

## Skills required

- [Low] Once the adversary has logical access (which can potentially require high knowledge and skill level), the adversary needs only the capability and facility to navigate the system through the OS graphical user interface or the command line.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.
- Employ robust identification and audit/blocking via using an allowlist of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
