# CAPEC-197: Exponential Data Expansion

<a id="capec-197"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: High  
Status: Draft  

An adversary submits data to a target application which contains nested exponential data expansion to produce excessively large output. Many data format languages allow the definition of macro-like structures that can be used to simplify the creation of complex structures. However, this capability can be abused to create excessive demands on a processor's CPU and memory. A small number of nested expansions can result in an exponential growth in demands on memory.

## Related CWE (2)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.
- [CWE-776: Improper Restriction of Recursive Entity References in DTDs](https://cwe.mitre.org/data/definitions/776.html): The product uses XML documents and allows their structure to be defined with a Document Type Definition (DTD), but it does not properly control the number of recursive definitions of entities.

## Prerequisites

- This type of attack requires that the target must receive input but either fail to provide an upper limit for entity expansion or provide a limit that is so large that it does not preclude significant resource consumption.

## Skills required

- [Low] Ability to craft nested data expansion messages.

## Consequences

- Availability / Unreliable Execution, Resource Consumption

## Mitigations

- Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.
- Implementation: For XML based data - disable altogether the use of inline DTD schemas when parsing XML objects. If a DTD must be used, normalize, filter and use an allowlist and parse with methods and routines that will detect entity expansion from untrusted sources.

## Related pages

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
