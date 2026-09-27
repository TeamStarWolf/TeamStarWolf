# CAPEC-296 — ICMP Information Request

<a id="capec-296"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary sends an ICMP Information Request to a host to determine if it will respond to this deprecated mechanism. ICMP Information Requests are a deprecated message type. Information Requests were originally used for diskless machines to automatically obtain their network configuration, but this message type has been superseded by more robust protocol implementations like DHCP.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to send an ICMP Type 15 Information Request and receive an ICMP Type 16 Information Reply in response.

## Skills required

- The adversary needs to know certain linux commands for this type of attack.:LEVEL:Low

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
