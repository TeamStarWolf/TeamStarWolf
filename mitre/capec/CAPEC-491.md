# CAPEC-491: Quadratic Data Expansion

<a id="capec-491"></a>

Abstraction: Detailed  
Status: Draft  

An adversary exploits macro-like substitution to cause a denial of service situation due to excessive memory being allocated to fully expand the data. The result of this denial of service could cause the application to freeze or crash. This involves defining a very large entity and using it multiple times in a single entity substitution. CAPEC-197 is a similar attack pattern, but it is easier to discover and defend against. This attack pattern does not perform multi-level substitution and therefore does not obviously appear to consume extensive resources.

## Related CWE (1)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- This type of attack requires a server that accepts serialization data which supports substitution and parses the data.

## Consequences

- Availability / Unreliable Execution, Resource Consumption

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.
- Implementation: For XML based data - disable altogether the use of inline DTD schemas when parsing XML objects. If a DTD must be used, normalize, filter and use an allowlist and parse with methods and routines that will detect entity expansion from untrusted sources.

## Related pages

- [CAPEC-197: Exponential Data Expansion](/mitre/capec/CAPEC-197.md), named in the description above
- [CAPEC-125: Flooding](/mitre/capec/CAPEC-125.md), also related to CWE-770
- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-770
- [CAPEC-147: XML Ping of the Death](/mitre/capec/CAPEC-147.md), also related to CWE-770
- [CAPEC-229: Serialized Data Parameter Blowup](/mitre/capec/CAPEC-229.md), also related to CWE-770
- [CAPEC-230: Serialized Data with Nested Payloads](/mitre/capec/CAPEC-230.md), also related to CWE-770
- [CAPEC-231: Oversized Serialized Data Payloads](/mitre/capec/CAPEC-231.md), also related to CWE-770
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
