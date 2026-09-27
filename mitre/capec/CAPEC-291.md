# CAPEC-291 — DNS Zone Transfers

<a id="capec-291"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An attacker exploits a DNS misconfiguration that permits a ZONE transfer. Some external DNS servers will return a list of IP address and valid hostnames. Under certain conditions, it may even be possible to obtain Zone data about the organization's internal network. When successful the attacker learns valuable information about the topology of the target organization, including information about p

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::Access to a DNS server that allows Zone transfers.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
