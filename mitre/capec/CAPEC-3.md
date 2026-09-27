# CAPEC-3 — Using Leading 'Ghost' Character Sequences to Bypass Input Filters

<a id="capec-3"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

Some APIs will strip certain leading characters from a string of parameters. An adversary can intentionally introduce leading ghost characters (extra characters that don't affect the validity of the request at the API layer) that enable the input to pass the filters and therefore process the adversary's input. This occurs when the targeted API will accept input data in several syntactic forms and

## Related CWE (12)

[CWE-173](/CWE_REFERENCE.md) [CWE-41](/CWE_REFERENCE.md) [CWE-172](/CWE_REFERENCE.md) [CWE-179](/CWE_REFERENCE.md) [CWE-180](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-183](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted API must ignore the leading ghost characters that are used to get past the filters for the semantics to be the same.::

**Skills required:** ::SKILL:The ability to make an API request, and knowledge of ghost characters that will not be filtered by any input validation. These ghost character

**Mitigations:** ::Use an allowlist rather than a denylist input validation.::Canonicalize all data prior to validation.::Take an iterative approach to input validation (defense in depth).::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
