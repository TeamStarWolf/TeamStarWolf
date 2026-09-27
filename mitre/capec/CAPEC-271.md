# CAPEC-271 — Schema Poisoning

<a id="capec-271"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low

An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected sta

## Related CWE (1)

[CWE-15](/CWE_REFERENCE.md)

**Prerequisites:** ::Some level of access to modify the target schema.::The schema used by the target application must be improperly secured against unauthorized modification and manipulation.::

**Mitigations:** ::Design: Protect the schema against unauthorized modification.::Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.::Implementation: F


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
