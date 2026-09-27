# CAPEC-290 — Enumerate Mail Exchange (MX) Records

<a id="capec-290"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** 

An adversary enumerates the MX records for a given via a DNS query. This type of information gathering returns the names of mail servers on the network. Mail servers are often not exposed to the Internet but are located within the DMZ of a network protected by a firewall. A side effect of this configuration is that enumerating the MX records for an organization my reveal the IP address of the fire

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary requires access to a DNS server that will return the MX records for a network.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
