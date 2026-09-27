# CAPEC-589 — DNS Blocking

<a id="capec-589"></a>

**Abstraction:** Detailed  
**Status:** Draft  

An adversary intercepts traffic and intentionally drops DNS requests based on content in the request. In this way, the adversary can deny the availability of specific services or content to the user even if the IP address is changed.

## Related CWE (1)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

## Prerequisites

- This attack requires the ability to conduct deep packet inspection with an In-Path device that can drop the targeted traffic and/or connection.

## Mitigations

- Hard Coded Alternate DNS server in applications
- Avoid dependence on DNS
- Include hosts file/IP address in the application.
- Ensure best practices with respect to communications channel protections.
- Use a .onion domain with Tor support

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
