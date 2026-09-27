# CAPEC-680 — Exploitation of Improperly Controlled Registers

<a id="capec-680"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary exploits missing or incorrectly configured access control within registers to read/write data that is not meant to be obtained or modified by a user.

## Related CWE (5)

- [CWE-1224 — Improper Restriction of Write-Once Bit Fields](https://cwe.mitre.org/data/definitions/1224.html)
- [CWE-1231 — Improper Prevention of Lock Bit Modification](https://cwe.mitre.org/data/definitions/1231.html)
- [CWE-1233 — Security-Sensitive Hardware Controls with Missing Lock Bit Protection](https://cwe.mitre.org/data/definitions/1233.html)
- [CWE-1262 — Improper Access Control for Register Interface](https://cwe.mitre.org/data/definitions/1262.html)
- [CWE-1283 — Mutable Attestation or Measurement Reporting Data](https://cwe.mitre.org/data/definitions/1283.html)

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged.

## Skills required

- Intricate knowledge of registers.:LEVEL:High

## Mitigations

- Design proper access control policies for hardware register access from software and ensure these policies are implemented in accordance with the specified design.
- Ensure security lock bit protections are reviewed for design inconsistencies and co

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
