# CAPEC-202: Create Malicious Client

<a id="capec-202"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

An adversary creates a client application to interface with a target service where the client violates assumptions the service makes about clients. Services that have designated client applications (as opposed to services that use general client applications, such as IMAP or POP mail servers which can interact with any IMAP or POP client) may assume that the client will follow specific procedures.

## Related CWE (1)

- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html): The product includes a server that relies on the client to implement a protection mechanism that is intended to protect the server.

## Prerequisites

- The targeted service must make assumptions about the behavior of the client application that interacts with it, which can be abused by an adversary.

## Related pages

- [CAPEC-21: Exploitation of Trusted Identifiers](/mitre/capec/CAPEC-21.md), also related to CWE-602
- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-602
- [CAPEC-162: Manipulating Hidden Fields](/mitre/capec/CAPEC-162.md), also related to CWE-602
- [CAPEC-207: Removing Important Client Functionality](/mitre/capec/CAPEC-207.md), also related to CWE-602
- [CAPEC-208: Removing/short-circuiting 'Purse' logic: removing/mutating 'cash' decrements](/mitre/capec/CAPEC-208.md), also related to CWE-602
- [CAPEC-383: Harvesting Information via API Event Monitoring](/mitre/capec/CAPEC-383.md), also related to CWE-602
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
