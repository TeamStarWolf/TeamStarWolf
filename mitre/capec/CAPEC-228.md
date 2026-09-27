# CAPEC-228 — DTD Injection

<a id="capec-228"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

An attacker injects malicious content into an application's DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

## Related CWE (1)

[CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must be running an XML based application that leverages DTDs.::

**Mitigations:** ::Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.::Implementation: Disallow the inclusion of DTDs as part of incoming messages.::Implementation: Use XML parsing tool


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
