# CAPEC-305 — TCP ACK Scan

<a id="capec-305"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary uses TCP ACK segments to gather information about firewall or ACL configuration. The purpose of this type of scan is to discover information about filter configurations rather than port state. This type of scanning is rarely useful alone, but when combined with SYN scanning, gives a more complete picture of the type of firewall rules that are present.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The adversary requires logical access to the target network. ACK scanning requires the use of raw sockets, and thus cannot be performed from some Windows systems (Windows XP SP 2, for example). On U

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
