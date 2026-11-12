# CAPEC-147: XML Ping of the Death

<a id="capec-147"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Low  
Status: Draft  

An attacker initiates a resource depletion attack where a large number of small XML messages are delivered at a sufficiently rapid rate to cause a denial of service or crash of the target. Transactions such as repetitive SOAP transactions can deplete resources faster than a simple flooding attack because of the additional resources used by the SOAP protocol and the resources necessary to process SOAP messages. The transactions used are immaterial as long as they cause resource utilization on the target. In other words, this is a normal flooding attack augmented by using messages that will require extra processing on the target.

## Related CWE (2)

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html): The product does not properly control the allocation and maintenance of a limited resource.
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html): The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## Prerequisites

- The target must receive and process XML transactions.

## Skills required

- [Low] To send small XML messages
- [High] To use distributed network to launch the attack

## Consequences

- Availability / Resource Consumption

## Mitigations

- Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval.
- Implementation: Provide for network flow control and traffic shaping to control access to the resources.

## Related pages

- [CAPEC-227: Sustained Client Engagement](/mitre/capec/CAPEC-227.md), also related to CWE-400
- [CAPEC-492: Regular Expression Exponential Blowup](/mitre/capec/CAPEC-492.md), also related to CWE-400
- [CAPEC-125: Flooding](/mitre/capec/CAPEC-125.md), also related to CWE-770
- [CAPEC-130: Excessive Allocation](/mitre/capec/CAPEC-130.md), also related to CWE-770
- [CAPEC-197: Exponential Data Expansion](/mitre/capec/CAPEC-197.md), also related to CWE-770
- [CAPEC-229: Serialized Data Parameter Blowup](/mitre/capec/CAPEC-229.md), also related to CWE-770
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
