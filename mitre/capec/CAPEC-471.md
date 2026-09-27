# CAPEC-471 — Search Order Hijacking

<a id="capec-471"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Stable  

An adversary exploits a weakness in an application's specification of external libraries to exploit the functionality of the loader where the process loading the library searches first in the same directory in which the process binary resides and then in other directories. Exploitation of this preferential search order can allow an attacker to make the loading process load the adversary's rogue li

## Mapped ATT&CK techniques (3)

- [T1574.001 — DLL](/mitre/techniques/T1574-001.md) — Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses.
- [T1574.004 — Dylib Hijacking](/mitre/techniques/T1574-004.md) — Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime.
- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md) — Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.

## Related CWE (1)

- [CWE-427 — Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html) — The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.

## Prerequisites

- Attacker has a mechanism to place its malicious libraries in the needed location on the file system.

## Skills required

- Ability to create a malicious library.:LEVEL:Medium

## Mitigations

- Design: Fix the Windows loading process to eliminate the preferential search order by looking for DLLs in the precise location where they are expected
- Design: Sign system DLLs so that unauthorized DLLs can be detected.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
