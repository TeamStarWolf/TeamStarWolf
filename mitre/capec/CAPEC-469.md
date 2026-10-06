# CAPEC-469: HTTP DoS

<a id="capec-469"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An attacker performs flooding at the HTTP level to bring down only a particular web application rather than anything listening on a TCP/IP connection. This denial of service attack requires substantially fewer packets to be sent which makes DoS harder to detect. This is an equivalent of SYN flood in HTTP. The idea is to keep the HTTP session alive indefinitely and then repeat that hundreds of times. This attack targets resource depletion weaknesses in web server software. The web server will wait to attacker's responses on the initiated HTTP sessions while the connection threads are being exhausted.

## Mapped ATT&CK techniques (1)

- [T1499.002: Service Exhaustion Flood](/mitre/techniques/T1499-002.md): Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).

## Related CWE (2)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.
- [CWE-772: Missing Release of Resource after Effective Lifetime](https://cwe.mitre.org/data/definitions/772.html): The product does not release a resource after its effective lifetime has ended, i.e., after the resource is no longer needed.

## Prerequisites

- HTTP protocol is usedWeb server used is vulnerable to denial of service via HTTP flooding

## Mitigations

- Configuration: Configure web server software to limit the waiting period on opened HTTP sessions
- Design: Use load balancing mechanisms

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
