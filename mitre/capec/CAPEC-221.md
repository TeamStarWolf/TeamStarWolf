# CAPEC-221 — Data Serialization External Entities Blowup

<a id="capec-221"></a>

**Abstraction:** Detailed  
**Status:** Draft  

This attack takes advantage of the entity replacement property of certain data serialization languages (e.g., XML, YAML, etc.) where the value of the replacement is a URI. A well-crafted file could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending o

## Related CWE (1)

- [CWE-611 — Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

## Prerequisites

- A server that has an implementation that accepts entities containing URI values.

## Mitigations

- This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
