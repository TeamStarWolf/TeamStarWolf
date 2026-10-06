# CAPEC-146: XML Schema Poisoning

<a id="capec-146"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Stable  

An adversary corrupts or modifies the content of XML schema information passed between a client and server for the purpose of undermining the security of the target. XML Schemas provide the structure and content definitions for XML documents. Schema poisoning is the ability to manipulate a schema either by replacing or modifying it to compromise the programs that process documents that use this schema.

## Related CWE (2)

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html): The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.

## Prerequisites

- Some level of access to modify the target schema.
- The schema used by the target application must be improperly secured against unauthorized modification and manipulation.

## Consequences

- Availability / Unreliable Execution, Resource Consumption
- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Design: Protect the schema against unauthorized modification.
- Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the XML document. Additionally, ensure that the proper permissions are set on local files to avoid unauthorized modification.
- Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
