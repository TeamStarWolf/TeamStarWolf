# CAPEC-528 — XML Flood

<a id="capec-528"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Low

An adversary may execute a flooding attack using XML messages with the intent to deny legitimate users access to a web service. These attacks are accomplished by sending a large number of XML based requests and letting the service attempt to parse each one. In many cases this type of an attack will result in a XML Denial of Service (XDoS) due to an application becoming unstable, freezing, or crash

## Mapped ATT&CK techniques (2)

- [T1498.001](/mitre/techniques/T1498-001.md)
- [T1499.002](/mitre/techniques/T1499-002.md)

## Related CWE (1)

[CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must receive and process XML transactions.::An adverssary must possess the ability to generate a large amount of XML based messages to send to the target service.::

**Skills required:** ::SKILL:Denial of service:LEVEL:Low::

**Mitigations:** ::Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval.::Implementation: Provide for network flow control and traffic 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
