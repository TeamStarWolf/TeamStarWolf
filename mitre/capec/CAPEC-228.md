# CAPEC-228: DTD Injection

<a id="capec-228"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An attacker injects malicious content into an application's DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

## Related CWE (1)

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html): The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The target must be running an XML based application that leverages DTDs.

## Mitigations

- Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.
- Implementation: Disallow the inclusion of DTDs as part of incoming messages.
- Implementation: Use XML parsing tools that protect against DTD attacks.

## Related pages

- [CAPEC-175: Code Inclusion](/mitre/capec/CAPEC-175.md), also related to CWE-829
- [CAPEC-201: Serialized Data External Linking](/mitre/capec/CAPEC-201.md), also related to CWE-829
- [CAPEC-251: Local Code Inclusion](/mitre/capec/CAPEC-251.md), also related to CWE-829
- [CAPEC-252: PHP Local File Inclusion](/mitre/capec/CAPEC-252.md), also related to CWE-829
- [CAPEC-253: Remote Code Inclusion](/mitre/capec/CAPEC-253.md), also related to CWE-829
- [CAPEC-263: Force Use of Corrupted Files](/mitre/capec/CAPEC-263.md), also related to CWE-829
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
