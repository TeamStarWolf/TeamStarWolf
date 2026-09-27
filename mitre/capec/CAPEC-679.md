# CAPEC-679 — Exploitation of Improperly Configured or Implemented Memory Protections

<a id="capec-679"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Medium

An adversary takes advantage of missing or incorrectly configured access control within memory to read/write data or inject malicious code into said memory.

## Related CWE (9)

[CWE-1222](/CWE_REFERENCE.md) [CWE-1252](/CWE_REFERENCE.md) [CWE-1257](/CWE_REFERENCE.md) [CWE-1260](/CWE_REFERENCE.md) [CWE-1274](/CWE_REFERENCE.md) [CWE-1282](/CWE_REFERENCE.md) [CWE-1312](/CWE_REFERENCE.md) [CWE-1316](/CWE_REFERENCE.md) [CWE-1326](/CWE_REFERENCE.md)

**Prerequisites:** ::Access to the hardware being leveraged.::

**Skills required:** ::SKILL:Ability to craft malicious code to inject into the memory region.:LEVEL:Medium::SKILL:Intricate knowledge of memory structures.:LEVEL:High::

**Mitigations:** ::Ensure that protected and unprotected memory ranges are isolated and do not overlap.::If memory regions must overlap, leverage memory priority schemes if memory regions can overlap.::Ensure that original and mirrored memory regions apply the same p


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
