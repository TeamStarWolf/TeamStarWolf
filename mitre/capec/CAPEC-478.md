# CAPEC-478 — Modification of Windows Service Configuration

<a id="capec-478"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Usable  

An adversary exploits a weakness in access control to modify the execution parameters of a Windows service. The goal of this attack is to execute a malicious binary in place of an existing service.

## Mapped ATT&CK techniques (2)

- [T1543.003 — Windows Service](/mitre/techniques/T1543-003.md)
- [T1574.011 — Services Registry Permissions Weakness](/mitre/techniques/T1574-011.md)

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## Prerequisites

- The adversary must have the capability to write to the Windows Registry on the targeted system.

## Mitigations

- Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
