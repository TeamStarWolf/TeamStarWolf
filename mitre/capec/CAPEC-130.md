# CAPEC-130: Excessive Allocation

<a id="capec-130"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

An adversary causes the target to allocate excessive resources to servicing the attackers' request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request.

## Mapped ATT&CK techniques (1)

- [T1499.003: Application Exhaustion Flood](/mitre/techniques/T1499-003.md): Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications.

## Related CWE (3)

- [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html): The product does not release or incorrectly releases a resource before it is made available for re-use.
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.
- [CWE-1325: Improperly Controlled Sequential Memory Allocation](https://cwe.mitre.org/data/definitions/1325.html): The product manages a group of objects or resources and performs a separate memory allocation for each object, but it does not properly limit the total amount of memory that is consumed by all of the combined objects.

## Prerequisites

- The target must accept service requests from the attacker and the adversary must be able to control the resource allocation associated with this request to be in excess of the normal allocation. The latter is usually accomplished through the presence of a bug on the target that allows the adversary to manipulate variables used in the allocation.

## Consequences

- Availability / Resource Consumption

## Mitigations

- Limit the amount of resources that are accessible to unprivileged users.
- Assume all input is malicious. Consider all potentially relevant properties when validating input.
- Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed.
- Use resource-limiting settings, if possible.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
