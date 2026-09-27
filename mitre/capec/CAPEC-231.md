# CAPEC-231 — Oversized Serialized Data Payloads

<a id="capec-231"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary injects oversized serialized data payloads into a parser during data processing to produce adverse effects upon the parser such as exhausting system resources and arbitrary code execution.

## Related CWE (4)

- [CWE-112 — Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-674 — Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Prerequisites

- An application uses an parser for serialized data to perform transformation on user-controllable data.
- An application does not perform sufficient validation to ensure that user-controllable data is

## Skills required

- Denial of service:LEVEL:Low
- Arbitrary code execution:LEVEL:High

## Mitigations

- Carefully validate and sanitize all user-controllable serialized data prior to passing it to the parser routine. Ensure that the resultant data is safe to pass to the parser.
- Perform validation on canonical data.
- Pick a robust implementation of t

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
