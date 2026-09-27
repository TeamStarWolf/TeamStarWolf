# CAPEC-125 — Flooding

<a id="capec-125"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Stable  

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latte

## Mapped ATT&CK techniques (2)

- [T1498.001 — Direct Network Flood](/mitre/techniques/T1498-001.md)
- [T1499 — Endpoint Denial of Service](/mitre/techniques/T1499.md)

## Related CWE (2)

- [CWE-404 — Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html)
- [CWE-770 — Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

## Prerequisites

- Any target that services requests is vulnerable to this attack on some level of scale.

## Mitigations

- Ensure that protocols have specific limits of scale configured.
- Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits.
- Uniformly throttle all requests in order to make it more dif

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
