# CAPEC-165 — File Manipulation

<a id="capec-165"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Status:** Draft  

An attacker modifies file contents or attributes (such as extensions or names) of files in a manner to cause incorrect processing by an application. Attackers use this class of attacks to cause applications to enter unstable states, overwrite or expose sensitive information, and even execute arbitrary code with the application's privileges. This class of attacks differs from attacks on configuration information (even if file-based) in that file manipulation causes the file processing to result in non-standard behaviors, such as buffer overflows or use of the incorrect interpreter. Configuration attacks rely on the application interpreting files correctly in order to insert harmful configuration information. Likewise, resource location attacks rely on controlling an application's ability to locate files, whereas File Manipulation attacks do not require the application to look in a non-default location, although the two classes of attacks are often combined.

## Mapped ATT&CK techniques (1)

- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md) — Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.

## Prerequisites

- The target must use the affected file without verifying its integrity.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
