# CAPEC-325 — TCP Congestion Control Flag (ECN) Probe

<a id="capec-325"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

This OS fingerprinting probe checks to see if the remote host supports explicit congestion notification (ECN) messaging. ECN messaging was designed to allow routers to notify a remote host when signal congestion problems are occurring. Explicit Congestion Notification messaging is defined by RFC 3168. Different operating systems and versions may or may not implement ECN notifications, or may respo

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
