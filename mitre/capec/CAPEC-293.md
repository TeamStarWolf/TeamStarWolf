# CAPEC-293 — Traceroute Route Enumeration

<a id="capec-293"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary uses a traceroute utility to map out the route which data flows through the network in route to a target destination. Tracerouting can allow the adversary to construct a working topology of systems and routers by listing the systems through which data passes through on their way to the targeted machine. This attack can return varied results depending upon the type of traceroute that is performed. Traceroute works by sending packets to a target while incrementing the Time-to-Live field in the packet header. As the packet traverses each hop along its way to the destination, its TTL expires generating an ICMP diagnostic message that identifies where the packet expired. Traditional techniques for tracerouting involved the use of ICMP and UDP, but as more firewalls began to filter ingress ICMP, methods of traceroute using TCP were developed.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- A network capable of routing the attackers' packets to the destination network.

## Consequences

- Confidentiality / Other

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
