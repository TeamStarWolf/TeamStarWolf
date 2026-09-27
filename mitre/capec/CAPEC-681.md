# CAPEC-681 — Exploitation of Improperly Controlled Hardware Security Identifiers

<a id="capec-681"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary takes advantage of missing or incorrectly configured security identifiers (e.g., tokens), which are used for access control within a System-on-Chip (SoC), to read/write data or execute a given action.

## Related CWE (5)

- [CWE-1259 — Improper Restriction of Security Token Assignment](https://cwe.mitre.org/data/definitions/1259.html)
- [CWE-1267 — Policy Uses Obsolete Encoding](https://cwe.mitre.org/data/definitions/1267.html)
- [CWE-1270 — Generation of Incorrect Security Tokens](https://cwe.mitre.org/data/definitions/1270.html)
- [CWE-1294 — Insecure Security Identifier Mechanism](https://cwe.mitre.org/data/definitions/1294.html)
- [CWE-1302 — Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)](https://cwe.mitre.org/data/definitions/1302.html)

## Prerequisites

- Awareness of the hardware being leveraged.
- Access to the hardware being leveraged.

## Skills required

- Ability to execute actions within the SoC.:LEVEL:Medium
- Intricate knowledge of the identifiers being utilized.:LEVEL:High

## Mitigations

- Review generation of security identifiers for design inconsistencies and common weaknesses.
- Review security identifier decoders for design inconsistencies and common weaknesses.
- Test security identifier definition, access, and programming flow in

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
