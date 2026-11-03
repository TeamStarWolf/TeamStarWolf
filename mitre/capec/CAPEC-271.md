# CAPEC-271: Schema Poisoning

<a id="capec-271"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected state, or recording incomplete data.

## Related CWE (1)

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.

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

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-15
- [CAPEC-69: Target Programs with Elevated Privileges](/mitre/capec/CAPEC-69.md), also related to CWE-15
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-15
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-15
- [CAPEC-146: XML Schema Poisoning](/mitre/capec/CAPEC-146.md), also related to CWE-15
- [CAPEC-176: Configuration/Environment Manipulation](/mitre/capec/CAPEC-176.md), also related to CWE-15
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
