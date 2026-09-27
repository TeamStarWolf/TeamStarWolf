# CAPEC-680 — Exploitation of Improperly Controlled Registers

<a id="capec-680"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An adversary exploits missing or incorrectly configured access control within registers to read/write data that is not meant to be obtained or modified by a user.

## Related CWE (5)

[CWE-1224](/CWE_REFERENCE.md) [CWE-1231](/CWE_REFERENCE.md) [CWE-1233](/CWE_REFERENCE.md) [CWE-1262](/CWE_REFERENCE.md) [CWE-1283](/CWE_REFERENCE.md)

**Prerequisites:** ::Awareness of the hardware being leveraged.::Access to the hardware being leveraged.::

**Skills required:** ::SKILL:Intricate knowledge of registers.:LEVEL:High::

**Mitigations:** ::Design proper access control policies for hardware register access from software and ensure these policies are implemented in accordance with the specified design.::Ensure security lock bit protections are reviewed for design inconsistencies and co


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
