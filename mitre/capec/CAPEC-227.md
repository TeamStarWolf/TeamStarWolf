# CAPEC-227: Sustained Client Engagement

<a id="capec-227"></a>

Abstraction: Meta  
Status: Draft  

An adversary attempts to deny legitimate users access to a resource by continually engaging a specific resource in an attempt to keep the resource tied up as long as possible. The adversary's primary goal is not to crash or flood the target, which would alert defenders; rather it is to repeatedly perform actions or abuse algorithmic flaws such that a given resource is tied up and not available to a legitimate user. By carefully crafting a requests that keep the resource engaged through what is seemingly benign requests, legitimate users are limited or completely denied access to the resource.

## Mapped ATT&CK techniques (1)

- [T1499: Endpoint Denial of Service](/mitre/techniques/T1499.md): Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.

## Related CWE (1)

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html): The product does not properly control the allocation and maintenance of a limited resource.

## Prerequisites

- This pattern of attack requires a temporal aspect to the servicing of a given request. Success can be achieved if the adversary can make requests that collectively take more time to complete than legitimate user requests within the same time frame.

## Mitigations

- Potential mitigations include requiring a unique login for each resource request, constraining local unprivileged access by disallowing simultaneous engagements of the resource, or limiting access to the resource to one access per IP address. In such scenarios, the adversary would have to increase engagements either by launching multiple sessions manually or programmatically to counter such defenses.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
