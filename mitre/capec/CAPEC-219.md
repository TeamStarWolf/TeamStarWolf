# CAPEC-219 — XML Routing Detour Attacks

<a id="capec-219"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** High

An attacker subverts an intermediate system used to process XML content and forces the intermediate to modify and/or re-route the processing of the content. XML Routing Detour Attacks are Adversary in the Middle type attacks (CAPEC-94). The attacker compromises or inserts an intermediate system in the processing of the XML message. For example, WS-Routing can be used to specify a series of nodes o

## Related CWE (2)

[CWE-441](/CWE_REFERENCE.md) [CWE-610](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted system must have multiple stages processing of XML content.::

**Skills required:** ::SKILL:To inject a bogus node in the XML routing table:LEVEL:Low::

**Mitigations:** ::Design: Specify maximum number intermediate nodes for the request and require SSL connections with mutual authentication.::Implementation: Use SSL for connections between all parties with mutual authentication.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
