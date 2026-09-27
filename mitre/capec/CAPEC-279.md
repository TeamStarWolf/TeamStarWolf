# CAPEC-279 — SOAP Manipulation

<a id="capec-279"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

Simple Object Access Protocol (SOAP) is used as a communication protocol between a client and server to invoke web services on the server. It is an XML-based protocol, and therefore suffers from many of the same shortcomings as other XML-based protocols. Adversaries can make use of these shortcomings and manipulate the content of SOAP paramters, leading to undesirable behavior on the server and al

## Related CWE (1)

[CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::An application uses SOAP-based web service api.::An application does not perform sufficient input validation to ensure that user-controllable data is safe for an XML parser.::The targeted server eit


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
