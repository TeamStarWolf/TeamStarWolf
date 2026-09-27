# CAPEC-330 — ICMP Error Message Echoing Integrity Probe

<a id="capec-330"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium

An adversary uses a technique to generate an ICMP Error message (Port Unreachable, Destination Unreachable, Redirect, Source Quench, Time Exceeded, Parameter Problem) from a target and then analyze the integrity of data returned or Quoted from the originating request that generated the error message.

## Related CWE (1)

[CWE-200](/CWE_REFERENCE.md)

**Prerequisites:** ::The ability to monitor and interact with network communications.Access to at least one host, and the privileges to interface with the network interface card.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
