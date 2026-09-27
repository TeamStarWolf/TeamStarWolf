# CAPEC-3 — Using Leading 'Ghost' Character Sequences to Bypass Input Filters

<a id="capec-3"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

Some APIs will strip certain leading characters from a string of parameters. An adversary can intentionally introduce leading ghost characters (extra characters that don't affect the validity of the request at the API layer) that enable the input to pass the filters and therefore process the adversary's input. This occurs when the targeted API will accept input data in several syntactic forms and

## Related CWE (12)

- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-41 — Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-179 — Incorrect Behavior Order: Early Validation](https://cwe.mitre.org/data/definitions/179.html)
- [CWE-180 — Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html)
- [CWE-181 — Incorrect Behavior Order: Validate Before Filter](https://cwe.mitre.org/data/definitions/181.html)
- [CWE-183 — Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-707 — Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)

## Prerequisites

- The targeted API must ignore the leading ghost characters that are used to get past the filters for the semantics to be the same.

## Skills required

- The ability to make an API request, and knowledge of ghost characters that will not be filtered by any input validation. These ghost character

## Mitigations

- Use an allowlist rather than a denylist input validation.
- Canonicalize all data prior to validation.
- Take an iterative approach to input validation (defense in depth).

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
