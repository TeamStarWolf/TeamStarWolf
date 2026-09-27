# CAPEC-51 — Poison Web Service Registry

<a id="capec-51"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

SOA and Web Services often use a registry to perform look up, get schema information, and metadata about services. A poisoned registry can redirect (think phishing for servers) the service requester to a malicious service provider, provide incorrect information in schema or metadata, and delete information about service provider interfaces.

## Related CWE (3)

[CWE-285](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must be able to write to resources or redirect access to the service registry.::

**Skills required:** ::SKILL:To identify and execute against an over-privileged system interface:LEVEL:Low::

**Mitigations:** ::Design: Enforce principle of least privilege::Design: Harden registry server and file access permissions::Implementation: Implement communications to and from the registry using secure protocols::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
