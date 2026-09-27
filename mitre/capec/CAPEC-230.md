# CAPEC-230 — Serialized Data with Nested Payloads

<a id="capec-230"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Applications often need to transform data in and out of a data format (e.g., XML and YAML) by using a parser. It may be possible for an adversary to inject data that may have an adverse effect on the parser when it is being processed. Many data format languages allow the definition of macro-like structures that can be used to simplify the creation of complex structures. By nesting these structures

## Related CWE (4)

- [CWE-112 — Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-674 — Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Prerequisites

- An application's user-controllable data is expressed in a language that supports subsitution.
- An application does not perform sufficient validation to ensure that user-controllable data is not mali

## Mitigations

- Carefully validate and sanitize all user-controllable data prior to passing it to the data parser routine. Ensure that the resultant data is safe to pass to the data parser.
- Perform validation on canonical data.
- Pick a robust implementation of th

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
