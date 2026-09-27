# CAPEC-642 — Replace Binaries

<a id="capec-642"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

Adversaries know that certain binaries will be regularly executed as part of normal processing. If these binaries are not protected with the appropriate file system permissions, it could be possible to replace them with malware. This malware might be executed at higher system permission levels. A variation of this pattern is to discover self-extracting installation packages that unpack binaries to

## Mapped ATT&CK techniques (3)

- [T1505.005 — Terminal Services DLL](/mitre/techniques/T1505-005.md) — Adversaries may abuse components of Terminal Services to enable persistent access to systems.
- [T1554 — Compromise Host Software Binary](/mitre/techniques/T1554.md) — Adversaries may modify host software binaries to establish persistent access to systems.
- [T1574.005 — Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md) — Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer.

## Related CWE (1)

- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) — The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.

## Prerequisites

- The attacker must be able to place the malicious binary on the target machine.

## Mitigations

- Insure that binaries commonly used by the system have the correct file permissions. Set operating system policies that restrict privilege elevation of non-Administrators. Use auditing tools to observe changes to system services.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
