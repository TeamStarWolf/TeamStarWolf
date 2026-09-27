# CAPEC-177 — Create files with the same name as files protected with a higher classification

<a id="capec-177"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Status:** Draft  

An attacker exploits file location algorithms in an operating system or application by creating a file with the same name as a protected or privileged file. The attacker could manipulate the system if the attacker-created file is trusted by the operating system or an application component that attempts to load the original file. Applications often load or include external files, such as libraries

## Mapped ATT&CK techniques (1)

- [T1036 — Masquerading](/mitre/techniques/T1036.md) — Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.

## Related CWE (1)

- [CWE-706 — Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html) — The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Prerequisites

- The target application must include external files. Most non-trivial applications meet this criterion.
- The target application does not verify that a located file is the one it was looking for throu

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
