# CAPEC-130 — Excessive Allocation

<a id="capec-130"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary causes the target to allocate excessive resources to servicing the attackers' request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt

## Mapped ATT&CK techniques (1)

- [T1499.003](/mitre/techniques/T1499-003.md)

## Related CWE (3)

[CWE-404](/CWE_REFERENCE.md) [CWE-770](/CWE_REFERENCE.md) [CWE-1325](/CWE_REFERENCE.md)

**Prerequisites:** ::The target must accept service requests from the attacker and the adversary must be able to control the resource allocation associated with this request to be in excess of the normal allocation. The

**Mitigations:** ::Limit the amount of resources that are accessible to unprivileged users.::Assume all input is malicious. Consider all potentially relevant properties when validating input.::Consider uniformly throttling all requests in order to make it more diffic


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
