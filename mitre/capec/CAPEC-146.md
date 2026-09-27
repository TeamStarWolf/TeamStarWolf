# CAPEC-146 — XML Schema Poisoning

<a id="capec-146"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

An adversary corrupts or modifies the content of XML schema information passed between a client and server for the purpose of undermining the security of the target. XML Schemas provide the structure and content definitions for XML documents. Schema poisoning is the ability to manipulate a schema either by replacing or modifying it to compromise the programs that process documents that use this sc

## Related CWE (2)

[CWE-15](/CWE_REFERENCE.md) [CWE-472](/CWE_REFERENCE.md)

**Prerequisites:** ::Some level of access to modify the target schema.::The schema used by the target application must be improperly secured against unauthorized modification and manipulation.::

**Mitigations:** ::Design: Protect the schema against unauthorized modification.::Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the XML document. Additionally, ensure 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
