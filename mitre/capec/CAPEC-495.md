# CAPEC-495 — UDP Fragmentation

<a id="capec-495"></a>

**Abstraction:** Standard  
**Status:** Draft  

An attacker may execute a UDP Fragmentation attack against a target server in an attempt to consume resources such as bandwidth and CPU. IP fragmentation occurs when an IP datagram is larger than the MTU of the route the datagram has to traverse. Typically the attacker will use large UDP packets over 1500 bytes of data which forces fragmentation as ethernet MTU is 1500 bytes. This attack is a variation on a typical UDP flood but it enables more network bandwidth to be consumed with fewer packets. Additionally it has the potential to consume server CPU resources and fill memory buffers associated with the processing and reassembling of fragmented packets.

## Related CWE (2)

- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.
- [CWE-404 — Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html) — The product does not release or incorrectly releases a resource before it is made available for re-use.

## Prerequisites

- This type of an attack requires the attacker to be able to generate fragmented IP traffic containing crafted data.

## Mitigations

- This attack may be mitigated by changing default cache sizes to be larger at the OS level. Additionally rules can be enforced to prune the cache with shorter timeouts for packet reassembly as the cache nears capacity.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
