# CAPEC-231 — Oversized Serialized Data Payloads

<a id="capec-231"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary injects oversized serialized data payloads into a parser during data processing to produce adverse effects upon the parser such as exhausting system resources and arbitrary code execution.

## Related CWE (4)

- [CWE-112 — Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html) — The product accepts XML from an untrusted source but does not validate the XML against the proper schema.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-674 — Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) — The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- An application uses an parser for serialized data to perform transformation on user-controllable data.
- An application does not perform sufficient validation to ensure that user-controllable data is safe for a data parser.

## Skills required

- [Low] Denial of service
- [High] Arbitrary code execution

## Consequences

- Availability / Resource Consumption
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Carefully validate and sanitize all user-controllable serialized data prior to passing it to the parser routine. Ensure that the resultant data is safe to pass to the parser.
- Perform validation on canonical data.
- Pick a robust implementation of the serialized data parser.
- Validate data against a valid schema or DTD prior to parsing.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
