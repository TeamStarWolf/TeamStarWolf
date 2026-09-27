# CAPEC-4 — Using Alternative IP Address Encodings

<a id="capec-4"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

This attack relies on the adversary using unexpected formats for representing IP addresses. Networked applications may expect network location information in a specific format, such as fully qualified domains names (FQDNs), URL, IP address, or IP Address ranges. If the location information is not validated against a variety of different possible encodings and formats, the adversary can use an alte

## Related CWE (2)

[CWE-291](/CWE_REFERENCE.md) [CWE-173](/CWE_REFERENCE.md)

**Prerequisites:** ::The target software must fail to anticipate all of the possible valid encodings of an IP/web address.::The adversary must have the ability to communicate with the server.::

**Skills required:** ::SKILL:The adversary has only to try IP address format combinations.:LEVEL:Low::

**Mitigations:** ::Design: Default deny access control policies::Design: Input validation routines should check and enforce both input data types and content against a positive specification. In regards to IP addresses, this should include the authorized manner for t


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
