# CAPEC-37 — Retrieve Embedded Sensitive Data

<a id="capec-37"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attacker examines a target system to find sensitive data that has been embedded within it. This information can reveal confidential contents, such as account numbers or individual keys/credentials that can be used as an intermediate step in a larger attack.

## Mapped ATT&CK techniques (2)

- [T1005 — Data from Local System](/mitre/techniques/T1005.md)
- [T1552.004 — Private Keys](/mitre/techniques/T1552-004.md)

## Related CWE (14)

- [CWE-226 — Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html)
- [CWE-311 — Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-525 — Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
- [CWE-312 — Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-314 — Cleartext Storage in the Registry](https://cwe.mitre.org/data/definitions/314.html)
- [CWE-315 — Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-318 — Cleartext Storage of Sensitive Information in Executable](https://cwe.mitre.org/data/definitions/318.html)
- [CWE-1239 — Improper Zeroization of Hardware Register](https://cwe.mitre.org/data/definitions/1239.html)
- [CWE-1258 — Exposure of Sensitive System Information Due to Uncleared Debug Information](https://cwe.mitre.org/data/definitions/1258.html)
- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html)
- [CWE-1272 — Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html)
- [CWE-1278 — Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques](https://cwe.mitre.org/data/definitions/1278.html)
- [CWE-1301 — Insufficient or Incomplete Data Removal within Hardware Component](https://cwe.mitre.org/data/definitions/1301.html)
- [CWE-1330 — Remanent Data Readable after Memory Erase](https://cwe.mitre.org/data/definitions/1330.html)

## Prerequisites

- In order to feasibly execute this type of attack, some valuable data must be present in client software.
- Additionally, this information must be unprotected, or protected in a flawed fashion, or thr

## Skills required

- The attacker must possess knowledge of client code structure as well as ability to reverse-engineer or decompile it or probe it in other ways.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
