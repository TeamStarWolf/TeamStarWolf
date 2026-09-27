# CAPEC-52 — Embedding NULL Bytes

<a id="capec-52"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

An adversary embeds one or more null bytes in input to the target software. This attack relies on the usage of a null-valued byte as a string terminator in many environments. The goal is for certain components of the target software to stop processing the input when it encounters the null byte(s).

## Related CWE (7)

[CWE-158](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::The program does not properly handle postfix NULL terminators::

**Skills required:** ::SKILL:Directory traversal:LEVEL:Medium::SKILL:Execution of arbitrary code:LEVEL:High::

**Mitigations:** ::Properly handle the NULL characters supplied as part of user input prior to doing anything with the data.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
