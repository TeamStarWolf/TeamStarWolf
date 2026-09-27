# CAPEC-227 — Sustained Client Engagement

<a id="capec-227"></a>

**Abstraction:** Meta  
**Typical severity:**   
**Likelihood:** 

An adversary attempts to deny legitimate users access to a resource by continually engaging a specific resource in an attempt to keep the resource tied up as long as possible. The adversary's primary goal is not to crash or flood the target, which would alert defenders; rather it is to repeatedly perform actions or abuse algorithmic flaws such that a given resource is tied up and not available to

## Mapped ATT&CK techniques (1)

- [T1499](/mitre/techniques/T1499.md)

## Related CWE (1)

[CWE-400](/CWE_REFERENCE.md)

**Prerequisites:** ::This pattern of attack requires a temporal aspect to the servicing of a given request. Success can be achieved if the adversary can make requests that collectively take more time to complete than le

**Mitigations:** ::Potential mitigations include requiring a unique login for each resource request, constraining local unprivileged access by disallowing simultaneous engagements of the resource, or limiting access to the resource to one access per IP address. In su


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
