# CAPEC-332 — ICMP IP 'ID' Field Error Message Probe

<a id="capec-332"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium

An adversary sends a UDP datagram having an assigned value to its internet identification field (ID) to a closed port on a target to observe the manner in which this bit is echoed back in the ICMP error message. This allows the attacker to construct a fingerprint of specific OS behaviors.

## Related CWE (1)

[CWE-204](/CWE_REFERENCE.md)

**Prerequisites:** ::The ability to monitor and interact with network communications. Access to at least one host, and the privileges to interface with the network interface card.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
