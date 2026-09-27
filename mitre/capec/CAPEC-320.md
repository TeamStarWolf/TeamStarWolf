# CAPEC-320 — TCP Timestamp Probe

<a id="capec-320"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

This OS fingerprinting probe examines the remote server's implementation of TCP timestamps. Not all operating systems implement timestamps within the TCP header, but when timestamps are used then this provides the attacker with a means to guess the operating system of the target. The attacker begins by probing any active TCP service in order to get response which contains a TCP timestamp. Differen

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.The target OS must support the TCP timest

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
