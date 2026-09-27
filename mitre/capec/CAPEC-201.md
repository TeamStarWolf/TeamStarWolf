# CAPEC-201 — Serialized Data External Linking

<a id="capec-201"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary creates a serialized data file (e.g. XML, YAML, etc...) that contains an external data reference. Because serialized data parsers may not validate documents with external references, there may be no checks on the nature of the reference in the external data. This can allow an adversary to open arbitrary files or connections, which may further lead to the adversary gaining access to in

## Related CWE (1)

- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Prerequisites

- The target must follow external data references without validating the validity of the reference target.

## Skills required

- To send serialized data messages with maliciously crafted schema.:LEVEL:Low

## Mitigations

- Configure the serialized data processor to only retrieve external entities from trusted sources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
