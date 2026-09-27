# CAPEC-482 — TCP Flood

<a id="capec-482"></a>

**Abstraction:** Standard  
**Status:** Draft  

An adversary may execute a flooding attack using the TCP protocol with the intent to deny legitimate users access to a service. These attacks exploit the weakness within the TCP protocol where there is some state information for the connection the server needs to maintain. This often involves the use of TCP SYN messages.

## Mapped ATT&CK techniques (3)

- [T1498.001 — Direct Network Flood](/mitre/techniques/T1498-001.md)
- [T1499.001 — OS Exhaustion Flood](/mitre/techniques/T1499-001.md)
- [T1499.002 — Service Exhaustion Flood](/mitre/techniques/T1499-002.md)

## Related CWE (1)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Prerequisites

- This type of an attack requires the ability to generate a large amount of TCP traffic to send to the target port of a functioning server.

## Mitigations

- To mitigate this type of an attack, an organization can monitor incoming packets and look for patterns in the TCP traffic to determine if the network is under an attack. The potential target may implement a rate limit on TCP SYN messages which woul

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
