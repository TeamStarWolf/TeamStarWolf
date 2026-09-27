# CAPEC-165 — File Manipulation

<a id="capec-165"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

An attacker modifies file contents or attributes (such as extensions or names) of files in a manner to cause incorrect processing by an application. Attackers use this class of attacks to cause applications to enter unstable states, overwrite or expose sensitive information, and even execute arbitrary code with the application's privileges. This class of attacks differs from attacks on configurati

## Mapped ATT&CK techniques (1)

- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md)

## Prerequisites

- The target must use the affected file without verifying its integrity.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
