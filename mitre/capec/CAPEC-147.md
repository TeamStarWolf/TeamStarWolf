# CAPEC-147 — XML Ping of the Death

<a id="capec-147"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low

An attacker initiates a resource depletion attack where a large number of small XML messages are delivered at a sufficiently rapid rate to cause a denial of service or crash of the target. Transactions such as repetitive SOAP transactions can deplete resources faster than a simple flooding attack because of the additional resources used by the SOAP protocol and the resources necessary to process S

## Related CWE (2)

[CWE-400](/CWE_REFERENCE.md) [CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must receive and process XML transactions.::

**Skills required:** ::SKILL:To send small XML messages:LEVEL:Low::SKILL:To use distributed network to launch the attack:LEVEL:High::

**Mitigations:** ::Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval.::Implementation: Provide for network flow control and traffic 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
