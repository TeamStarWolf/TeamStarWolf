# CAPEC-489 — SSL Flood

<a id="capec-489"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An adversary may execute a flooding attack using the SSL protocol with the intent to deny legitimate users access to a service by consuming all the available resources on the server side. These attacks take advantage of the asymmetric relationship between the processing power used by the client and the processing power used by the server to create a secure connection. In this manner the attacker c

## Mapped ATT&CK techniques (1)

- [T1499.002](/mitre/techniques/T1499-002.md)

## Related CWE (1)

[CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the ability to generate a large amount of SSL traffic to send a target server.::

**Mitigations:** ::To mitigate this type of an attack, an organization can create rule based filters to silently drop connections if too many are attempted in a certain time period.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
