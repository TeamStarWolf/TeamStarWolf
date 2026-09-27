# CAPEC-681 — Exploitation of Improperly Controlled Hardware Security Identifiers

<a id="capec-681"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

An adversary takes advantage of missing or incorrectly configured security identifiers (e.g., tokens), which are used for access control within a System-on-Chip (SoC), to read/write data or execute a given action.

## Related CWE (5)

[CWE-1259](/CWE_REFERENCE.md) [CWE-1267](/CWE_REFERENCE.md) [CWE-1270](/CWE_REFERENCE.md) [CWE-1294](/CWE_REFERENCE.md) [CWE-1302](/CWE_REFERENCE.md)

**Prerequisites:** ::Awareness of the hardware being leveraged.::Access to the hardware being leveraged.::

**Skills required:** ::SKILL:Ability to execute actions within the SoC.:LEVEL:Medium::SKILL:Intricate knowledge of the identifiers being utilized.:LEVEL:High::

**Mitigations:** ::Review generation of security identifiers for design inconsistencies and common weaknesses.::Review security identifier decoders for design inconsistencies and common weaknesses.::Test security identifier definition, access, and programming flow in


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
