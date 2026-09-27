# CAPEC-37 — Retrieve Embedded Sensitive Data

<a id="capec-37"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

An attacker examines a target system to find sensitive data that has been embedded within it. This information can reveal confidential contents, such as account numbers or individual keys/credentials that can be used as an intermediate step in a larger attack.

## Mapped ATT&CK techniques (2)

- [T1005](/mitre/techniques/T1005.md)
- [T1552.004](/mitre/techniques/T1552-004.md)

## Related CWE (14)

[CWE-226](/CWE_REFERENCE.md) [CWE-311](/CWE_REFERENCE.md) [CWE-525](/CWE_REFERENCE.md) [CWE-312](/CWE_REFERENCE.md) [CWE-314](/CWE_REFERENCE.md) [CWE-315](/CWE_REFERENCE.md) [CWE-318](/CWE_REFERENCE.md) [CWE-1239](/CWE_REFERENCE.md) [CWE-1258](/CWE_REFERENCE.md) [CWE-1266](/CWE_REFERENCE.md) [CWE-1272](/CWE_REFERENCE.md) [CWE-1278](/CWE_REFERENCE.md) [CWE-1301](/CWE_REFERENCE.md) [CWE-1330](/CWE_REFERENCE.md)

**Prerequisites:** ::In order to feasibly execute this type of attack, some valuable data must be present in client software.::Additionally, this information must be unprotected, or protected in a flawed fashion, or thr

**Skills required:** ::SKILL:The attacker must possess knowledge of client code structure as well as ability to reverse-engineer or decompile it or probe it in other ways.


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
