# CAPEC-125: Flooding

<a id="capec-125"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: High  
Status: Stable  

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target's operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target.

## Mapped ATT&CK techniques (2)

- [T1498.001: Direct Network Flood](/mitre/techniques/T1498-001.md): Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.
- [T1499: Endpoint Denial of Service](/mitre/techniques/T1499.md): Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.

## Related CWE (2)

- [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html): The product does not release or incorrectly releases a resource before it is made available for re-use.
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- Any target that services requests is vulnerable to this attack on some level of scale.

## Consequences

- Availability / Unreliable Execution, Resource Consumption

## Mitigations

- Ensure that protocols have specific limits of scale configured.
- Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits.
- Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

## Related pages

- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-404 and CWE-770
- [CAPEC-494: TCP Fragmentation](/mitre/capec/CAPEC-494.md), also related to CWE-404 and CWE-770
- [CAPEC-495: UDP Fragmentation](/mitre/capec/CAPEC-495.md), also related to CWE-404 and CWE-770
- [CAPEC-496: ICMP Fragmentation](/mitre/capec/CAPEC-496.md), also related to CWE-404 and CWE-770
- [CAPEC-131: Resource Leak Exposure](/mitre/capec/CAPEC-131.md), also related to CWE-404
- [CAPEC-666: BlueSmacking](/mitre/capec/CAPEC-666.md), also related to CWE-404
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Cybercrime and Hacktivism in Four Books: Kingpin, Fatal System Error, We Are Anonymous, The Hacker Crackdown](/case-studies/CYBERCRIME_FOUR_BOOKS.md)
- [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
