# CAPEC-231 — Oversized Serialized Data Payloads

<a id="capec-231"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary injects oversized serialized data payloads into a parser during data processing to produce adverse effects upon the parser such as exhausting system resources and arbitrary code execution.

## Related CWE (4)

[CWE-112](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-674](/CWE_REFERENCE.md) [CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::An application uses an parser for serialized data to perform transformation on user-controllable data.::An application does not perform sufficient validation to ensure that user-controllable data is

**Skills required:** ::SKILL:Denial of service:LEVEL:Low::SKILL:Arbitrary code execution:LEVEL:High::

**Mitigations:** ::Carefully validate and sanitize all user-controllable serialized data prior to passing it to the parser routine. Ensure that the resultant data is safe to pass to the parser.::Perform validation on canonical data.::Pick a robust implementation of t


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
