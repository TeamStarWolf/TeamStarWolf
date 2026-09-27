# CAPEC-230 — Serialized Data with Nested Payloads

<a id="capec-230"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Applications often need to transform data in and out of a data format (e.g., XML and YAML) by using a parser. It may be possible for an adversary to inject data that may have an adverse effect on the parser when it is being processed. Many data format languages allow the definition of macro-like structures that can be used to simplify the creation of complex structures. By nesting these structures, causing the data to be repeatedly substituted, an adversary can cause the parser to consume more resources while processing, causing excessive memory consumption and CPU utilization.

## Related CWE (4)

- [CWE-112 — Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html) — The product accepts XML from an untrusted source but does not validate the XML against the proper schema.
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-674 — Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html) — The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- An application's user-controllable data is expressed in a language that supports subsitution.
- An application does not perform sufficient validation to ensure that user-controllable data is not malicious.

## Consequences

- Availability / Resource Consumption
- Confidentiality / Read Data
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Carefully validate and sanitize all user-controllable data prior to passing it to the data parser routine. Ensure that the resultant data is safe to pass to the data parser.
- Perform validation on canonical data.
- Pick a robust implementation of the data parser.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
