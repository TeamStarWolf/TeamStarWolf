# CAPEC-493 — SOAP Array Blowup

<a id="capec-493"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An adversary may execute an attack on a web service that uses SOAP messages in communication. By sending a very large SOAP array declaration to the web service, the attacker forces the web service to allocate space for the array elements before they are parsed by the XML parser. The attacker message is typically small in size containing a large array declaration of say 1,000,000 elements and a cou

## Related CWE (1)

[CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the attacker to know the endpoint of the web service, and be able to reach the endpoint with a malicious SOAP message.::

**Mitigations:** ::Enforce strict schema validation. The schema should enforce a maximum number of array elements. If the number of maximum array elements can't be limited another validation method should be used. One such method could be comparing the declared numbe


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
