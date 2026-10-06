# CAPEC-528: XML Flood

<a id="capec-528"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: Low  
Status: Draft  

An adversary may execute a flooding attack using XML messages with the intent to deny legitimate users access to a web service. These attacks are accomplished by sending a large number of XML based requests and letting the service attempt to parse each one. In many cases this type of an attack will result in a XML Denial of Service (XDoS) due to an application becoming unstable, freezing, or crashing.

## Mapped ATT&CK techniques (2)

- [T1499.002: Service Exhaustion Flood](/mitre/techniques/T1499-002.md): Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- [T1498.001: Direct Network Flood](/mitre/techniques/T1498-001.md): Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.

## Related CWE (1)

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- The target must receive and process XML transactions.
- An adverssary must possess the ability to generate a large amount of XML based messages to send to the target service.

## Skills required

- [Low] Denial of service

## Consequences

- Availability / Resource Consumption

## Mitigations

- Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval.
- Implementation: Provide for network flow control and traffic shaping to control access to the resources.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
