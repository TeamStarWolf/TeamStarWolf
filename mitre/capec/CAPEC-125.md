# CAPEC-125 — Flooding

<a id="capec-125"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Stable  

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latte

## Mapped ATT&CK techniques (2)

- [T1498.001 — Direct Network Flood](/mitre/techniques/T1498-001.md) — Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.
- [T1499 — Endpoint Denial of Service](/mitre/techniques/T1499.md) — Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.

## Related CWE (2)

- [CWE-404 — Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html) — The product does not release or incorrectly releases a resource before it is made available for re-use.
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html) — The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- Any target that services requests is vulnerable to this attack on some level of scale.

## Mitigations

- Ensure that protocols have specific limits of scale configured.
- Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits.
- Uniformly throttle all requests in order to make it more dif

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
