# CAPEC-221: Data Serialization External Entities Blowup

<a id="capec-221"></a>

Abstraction: Detailed  
Status: Draft  

This attack takes advantage of the entity replacement property of certain data serialization languages (e.g., XML, YAML, etc.) where the value of the replacement is a URI. A well-crafted file could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

## Related CWE (1)

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html): The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.

## Prerequisites

- A server that has an implementation that accepts entities containing URI values.

## Consequences

- Availability / Resource Consumption
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands

## Mitigations

- This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.
- This attack may be mitigated by tweaking the serialized data parser to not resolve external entities. If external entities are needed, then implement a custom resolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

## Related pages

- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
