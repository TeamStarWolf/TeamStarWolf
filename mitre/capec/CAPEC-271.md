# CAPEC-271 — Schema Poisoning

<a id="capec-271"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected state, or recording incomplete data.

## Related CWE (1)

- [CWE-15 — External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html) — One or more system settings or configuration elements can be externally controlled by a user.

## Prerequisites

- Some level of access to modify the target schema.
- The schema used by the target application must be improperly secured against unauthorized modification and manipulation.

## Consequences

- Availability / Unreliable Execution, Resource Consumption
- Integrity / Modify Data
- Confidentiality / Read Data

## Mitigations

- Design: Protect the schema against unauthorized modification.
- Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.
- Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
